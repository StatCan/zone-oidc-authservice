// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func loggerForRequest(r *http.Request) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"ip":      getUserIP(r),
		"request": r.URL.String(),
	})
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func returnStatus(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(msg))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func returnJSONMessage(w http.ResponseWriter, statusCode int, jsonMsg interface{}) {
	jsonBytes, err := json.Marshal(jsonMsg)
	if err != nil {
		log.Errorf("Failed to marshal struct to json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err = w.Write(jsonBytes)
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func getEnvOrDefault(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Println("No ", key, " specified, using '"+fallback+"' as default.")
		return fallback
	}
	return value
}

func getURLEnvOrDie(URLEnv string) *url.URL {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.Parse(envContent)
	if err != nil {
		log.Fatal("Not a valid URL for env variable ", URLEnv, ": ", envContent, "\n")
	}

	return parsedURL
}

func getEnvOrDie(envVar string) string {
	envContent := os.Getenv(envVar)

	if len(envContent) == 0 {
		log.Fatal("Env variable ", envVar, " missing, exiting.")
	}

	return envContent
}

func clean(s []string) []string {
	res := []string{}
	for _, elem := range s {
		if elem != "" {
			res = append(res, elem)
		}
	}
	return res
}

func createNonce(length int) string {
	nonceChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	var nonce = make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func setTLSContext(ctx context.Context, caBundle []byte) context.Context {
	if len(caBundle) == 0 {
		return ctx
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Warning("Could not load system cert pool")
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(caBundle); !ok {
		log.Warning("Could not append custom CA bundle, using system certs only")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs},
	}
	tlsConf := &http.Client{Transport: tr}
	return context.WithValue(ctx, oauth2.HTTPClient, tlsConf)
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	// TODO: Consider retrying the request if response code is 503
	// See: https://tools.ietf.org/html/rfc7009#section-2.2.1
	return client.Do(req.WithContext(ctx))
}

// Zone: Helper function to convert the userID(email) into a namespace value
func getNamespaceFromEmail(email string) string {
	namespaceName := ""

	split_userID := strings.Split(email, "@")
	if len(split_userID) > 0 {
		username := split_userID[0]

		// Remove any non-alphanumeric and non-underscore character from username
		regexNonAlpha := regexp.MustCompile(`[^\w]|\.`)
		regexNonAlphaResult := regexNonAlpha.ReplaceAllString(username, "-")

		// Remove any leading or trailing underscores from username
		regexTrail := regexp.MustCompile(`^-+|-+$|_`)
		regexTrailResult := regexTrail.ReplaceAllString(regexNonAlphaResult, "")

		// lower case the namespace value
		namespaceName = strings.ToLower(regexTrailResult)
	}

	return namespaceName
}

// Zone: Updates the K8s secret for the authenticated user's with their authservice session cookie value and the access token's expiry time.
// If the secret exist already, then create it.
func updateZoneSecret(kubeclient *kubernetes.Clientset, namespace string, tokenExpiry string, cookieValue string) error {
	// Get the access tokens secret
	secret, err := kubeclient.CoreV1().Secrets(namespace).Get(context.TODO(), AccessTokenSecretName, metav1.GetOptions{})
	if err != nil {
		// if the secret is not found, proceed to create it
		if k8serrors.IsNotFound(err) {
			secret = &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: AccessTokenSecretName,
				},
				// stringData allows passing plain text; K8s encodes it to Base64 automatically
				StringData: map[string]string{
					"expiry":          tokenExpiry,
					userSessionCookie: cookieValue,
				},
				Type: v1.SecretTypeOpaque,
			}

			_, err := kubeclient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			// return the error if it is not a NotFound error
			return err
		}
	}

	// if the secret exists, just update it
	secret.Data = map[string][]byte{
		"expiry":          []byte(tokenExpiry),
		userSessionCookie: []byte(cookieValue),
	}

	_, err = kubeclient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

// Zone: Gets the namespace of the requesting user
// and the authservice session ID value from the cookies of the ResponseWriter.
// Proceeds to create/update the user's authservice k8s secret.
func setupZoneK8sSecret(w http.ResponseWriter, userID string, kubeclient *kubernetes.Clientset, oauth2Tokens *oauth2.Token) error {
	// Get namespace from userID(which should be an email)
	namespace := getNamespaceFromEmail(userID)
	if namespace == "" {
		return fmt.Errorf("Couldn't get namespace for userID: %s. Skipping creating the K8s secret", userID)
	}

	// The authservice cookie should be the only one set
	rawCookie := w.Header().Values("Set-Cookie")[0]
	// Parse the raw string value into a cookie object
	cookie, err := http.ParseSetCookie(rawCookie)
	if err != nil {
		return fmt.Errorf("Failed to parse the session cookie: %v", err)
	} else if cookie.Name != userSessionCookie {
		return errors.New("Failed to get the authservice cookie")
	}

	// Create or update the authservice k8s secret
	err = updateZoneSecret(kubeclient, namespace, oauth2Tokens.Expiry.String(), cookie.Value)
	if err != nil {
		return fmt.Errorf("Error updating secret for access token in namespace %s: %v", namespace, err)
	}

	return nil
}
