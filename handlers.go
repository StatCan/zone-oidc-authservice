// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	userSessionCookie       = "authservice_session"
	userSessionUserID       = "userid"
	userSessionClaims       = "claims"
	userSessionIDToken      = "idtoken"
	userSessionOAuth2Tokens = "oauth2tokens"

	AccessTokenSecretName = "oidc-authservice-token"
)

func init() {
	// Register type for claims.
	gob.Register(map[string]interface{}{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.IDToken{})
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Check header for auth information.
	// Adding it to a cookie to treat both cases uniformly.
	// This is also required by the gorilla/sessions package.
	// TODO(yanniszark): change to standard 'Authorization: Bearer <value>' header
	bearer := r.Header.Get("X-Auth-Token")
	if bearer != "" {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Check if user session is valid
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Couldn't get user session.")
		return
	}
	// User is logged in
	if !session.IsNew {
		// Add userid header
		userID := session.Values["userid"].(string)
		if userID != "" {
			w.Header().Set(s.userIDOpts.header, s.userIDOpts.prefix+userID)
		}
		if s.userIDOpts.tokenHeader != "" {
			w.Header().Set(s.userIDOpts.tokenHeader, session.Values["idtoken"].(string))
		}
		returnStatus(w, http.StatusOK, "OK")
		return
	}

	// User is NOT logged in.
	// Initiate OIDC Flow with Authorization Request.
	state := newState(r.URL.String())
	id, err := state.save(s.store)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	selectAccountOption := oauth2.SetAuthURLParam("prompt", "select_account")
	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(id, selectAccountOption), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Get authorization code from authorization response.
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		logger.Error("Missing url parameter: code")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: code")
		return
	}

	// Get state and:
	// 1. Confirm it exists in our memory.
	// 2. Get the original URL associated with it.
	var stateID = r.FormValue("state")
	if len(stateID) == 0 {
		logger.Error("Missing url parameter: state")
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	state, err := load(s.store, stateID)
	if err != nil {
		logger.Errorf("Failed to retrieve state from store: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to retrieve state.")
	}

	ctx := setTLSContext(r.Context(), s.caBundle)
	// Exchange the authorization code with {access, refresh, id}_token
	oauth2Tokens, err := s.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		logger.Errorf("Failed to exchange authorization code with token: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
		return
	}

	rawIDToken, ok := oauth2Tokens.Extra("id_token").(string)
	if !ok {
		logger.Error("No id_token field available.")
		returnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	verifiedIdToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// Get the claims from the idtoken.
	// ZONE: We changed this because getting the claims from the userInfo
	// with s.provider.UserInfo like in upstream was failing
	claims := map[string]interface{}{}
	if err := verifiedIdToken.Claims(&claims); err != nil {
		logger.Errorf("Not able to get ID token claims: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Not able to get ID token claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"

	// make sure userId claim was retrieved succesfully
	userID, ok := claims[s.userIDOpts.claim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.userIDOpts.claim, claims)
		returnStatus(w, http.StatusInternalServerError,
			fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.userIDOpts.claim))
		return
	}

	session.Values[userSessionUserID] = userID
	session.Values[userSessionClaims] = claims
	session.Values[userSessionIDToken] = rawIDToken
	session.Values[userSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
	}

	// ZONE: Get the authservice cookie value to store it in a k8s secret for easy access with calls from notebook pods
	if err := setupZoneK8sSecret(w, userID, s.kubeclient, s.roleBindingLister, oauth2Tokens); err != nil {
		logger.Errorf("Couldn't create or update the oidc-authservice secret: %v", err)
	}

	logger.Infof("Login validated for %s with ID token, redirecting.", userID)

	// Getting original destination from DB with state
	var destination = state.origURL
	if s.staticDestination != "" {
		destination = s.staticDestination
	}

	http.Redirect(w, r, destination, http.StatusFound)
}

// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Revoke user session.
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if session.IsNew {
		logger.Warn("Request doesn't have a valid session.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Check if the provider has a revocation_endpoint
	_revocationEndpoint, err := revocationEndpoint(s.provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		ctx := setTLSContext(r.Context(), s.caBundle)
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		err := revokeTokens(ctx, _revocationEndpoint, &token, s.oauth2Config.ClientID, s.oauth2Config.ClientSecret)
		if err != nil {
			logger.Errorf("Error revoking tokens: %v", err)
			statusCode := http.StatusInternalServerError
			// If the server returned 503, return it as well as the client might want to retry
			if reqErr, ok := errors.Cause(err).(*requestError); ok {
				if reqErr.StatusCode == http.StatusServiceUnavailable {
					statusCode = reqErr.StatusCode
				}
			}
			returnStatus(w, statusCode, "Failed to revoke access/refresh tokens, please try again")
			return
		}
		logger.WithField("userid", session.Values[userSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	session.Options.MaxAge = -1
	if err := sessions.Save(r, w); err != nil {
		logger.Errorf("Couldn't delete user session: %v", err)
	}
	logger.Info("Successful logout.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// readiness is the handler that checks if the authservice is ready for serving
// requests.
// Currently, it checks if the provider is nil, meaning that the setup hasn't finished yet.
func readiness(isReady *abool.AtomicBool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		if !isReady.IsSet() {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
	}
}

func whitelistMiddleware(whitelist []string, isReady *abool.AtomicBool) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := loggerForRequest(r)
			// Check whitelist
			for _, prefix := range whitelist {
				if strings.HasPrefix(r.URL.Path, prefix) {
					logger.Infof("URI is whitelisted. Accepted without authorization.")
					returnStatus(w, http.StatusOK, "OK")
					return
				}
			}
			// If server is not ready, return 503.
			if !isReady.IsSet() {
				returnStatus(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
				return
			}
			// Server ready, continue.
			handler.ServeHTTP(w, r)
		})
	}
}

// Zone: Creates an HTTP request object for the on-behalf-of flow
// to get a new access token from an existing token.
func (s *server) getOnBehalfOfRequest(requestScope string, accessToken string) (*http.Request, error) {
	data := url.Values{}
	data.Set("client_id", s.oauth2Config.ClientID)
	data.Set("client_secret", s.oauth2Config.ClientSecret)
	data.Set("scope", requestScope)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", accessToken)
	data.Set("requested_token_use", "on_behalf_of")

	req, err := http.NewRequest("POST", s.provider.Endpoint().TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// ZONE: Custom endpoint for the on-behalf-of flow to acquire a new access token.
// This endpoint is expected to be called from a k8s pod, and will try to get the source namespace.
// Gets the authservice session from the value in a k8s secret from the source namespace.
// Refreshes the user's access token from their session if needed before doing OBO.
// This avoids saving the refreshed access token in the session to avoid a bug that would wipe the session after saving.
// Requires a "scope" GET parameter to be passed to the OBO flow.
// Returns the access token response from the OBO call plus the "exp" claim value to be used by the Zone token broker in our notebook images
func (s *server) getPassthroughToken(w http.ResponseWriter, r *http.Request) {
	logger := loggerForRequest(r)

	logger.Info("Getting a passthrough token...")

	// Get the desired scope from the request parameters
	requestScope := r.URL.Query().Get("scope")
	if requestScope == "" {
		logger.Errorf("Missing parameter: scope")
		returnStatus(w, http.StatusBadRequest, "Missing parameter: scope")
		return
	}

	// get source pod IP (no port)
	sourceIP := strings.Split(r.RemoteAddr, ":")[0]

	// Gets the namespace of the requesting pod using the source IP
	pods, err := s.kubeclient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: "status.podIP=" + sourceIP,
	})
	if err != nil {
		logger.Errorf("Failed to get pods with remote address %s : %+v", sourceIP, err)
		returnStatus(w, http.StatusForbidden, "Error: Unable to determine the source namespace of the request")
		return
	} else if pods == nil || pods != nil && pods.Size() == 0 {
		logger.Errorf("No pods found with source IP %s", sourceIP)
		returnStatus(w, http.StatusForbidden, "Error: Unable to determine the source namespace of the request")
		return
	}

	namespace := pods.Items[0].Namespace

	// Get the access token secret from the requesting namespace
	secret, err := s.kubeclient.CoreV1().Secrets(namespace).Get(context.TODO(), AccessTokenSecretName, metav1.GetOptions{})
	if err != nil {
		logger.Errorf("Error getting access token from secret in namespace %s: %v", namespace, err)
		returnStatus(w, http.StatusInternalServerError, "Error: Unable to get initial access token for passthrough authentication")
		return
	}

	// Get the session from the cookie value stored in the k8s secret and add it to the request
	// This step is needed for store.Get to retrieve and decrypt the sessionID value
	r.AddCookie(&http.Cookie{
		Name:  userSessionCookie,
		Value: string(secret.Data[userSessionCookie]),
	})

	// Get the session object for the requesting user
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Couldn't get user session.")
		return
	}
	if session.IsNew {
		logger.Error("Failed to retrieve a valid session")
		returnStatus(w, http.StatusInternalServerError, "Failed to retrieve a valid session")
		return
	}

	ctx := setTLSContext(r.Context(), s.caBundle)

	// Get the initial access token from the user's session
	token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
	// Refreshes the initial access token if needed
	tokenSource := s.oauth2Config.TokenSource(ctx, &token)
	newToken, err := tokenSource.Token()
	if err != nil {
		logger.Errorf("Failed to refresh token: %v", err)
		returnStatus(w, http.StatusInternalServerError, fmt.Sprintf("Failed to refresh token: %v", err))
		return
	}

	// Get the on-behalf-of request object
	req, err := s.getOnBehalfOfRequest(requestScope, newToken.AccessToken)
	if err != nil {
		logger.Errorf("Error creating on-behalf-of request: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Error: Unable to create on-behalf-of request")
		return
	}

	// Send the on-behalf-of request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		logger.Errorf("Error while sending sending on-behalf-of request for namespace %s: %v", namespace, err)
		returnStatus(w, http.StatusInternalServerError, "Error while sending on-behalf-of request")
		return
	}

	defer res.Body.Close()

	// return the error if the response is not 200
	if res.StatusCode != http.StatusOK {
		// Read the response body and convert to string
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			logger.Errorf("Error while processing on-behalf-of response for namespace %s: %v", namespace, err)
			returnStatus(w, http.StatusInternalServerError, "Error while processing on-behalf-of response")
			return
		}
		bodyString := string(bodyBytes)

		returnStatus(w, res.StatusCode, bodyString)
		return
	}

	// Convert response body to JSON
	decoder := json.NewDecoder(res.Body)
	tokenResponse := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
		ExpiresOn   int64  `json:"expires_on"` // Not actually in response body
	}{}
	err = decoder.Decode(&tokenResponse)
	if err != nil {
		logger.Errorf("Error decoding response for new access token: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Error processing on-behalf-of response")
		return
	}

	// Sets a default value for the expiry date based on the "expires_in" seconds value
	tokenResponse.ExpiresOn = time.Now().Unix() + tokenResponse.ExpiresIn

	// There may be a few seconds of inaccuracy in the default expiresOn value
	// so we try to get the real value from the token response's "exp" claim.
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(tokenResponse.AccessToken, jwt.MapClaims{})

	// if there is an error parsing the token for the "exp" claim, just log the error.
	// the response will use the default set value
	if err != nil {
		logger.Errorf("Error parsing On-Behalf-Of JWT access token: %v", err)
	} else {
		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			// Check for the "exp" claim in the token
			exp, ok := claims["exp"].(float64)
			if !ok {
				logger.Error("Failed to convert \"exp\" token value to float64")
			} else {
				// Set the "exp" claim value for the passthrough token response
				tokenResponse.ExpiresOn = int64(exp)
			}
		} else {
			// Log error if claims are not ok
			logger.Error("Error getting claims from access token")
		}
	}

	// return the new on-behalf-of token for the desired scope
	returnJSONMessage(w, http.StatusOK, tokenResponse)
	return
}
