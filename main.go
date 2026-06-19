// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"github.com/tevino/abool"
	"github.com/yosssi/boltstore/reaper"
	"github.com/yosssi/boltstore/store"
	"golang.org/x/oauth2"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/rbac/v1"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// Option Defaults
const (
	defaultHealthServerPort  = "8081"
	defaultServerHostname    = ""
	defaultServerPort        = "8080"
	defaultUserIDHeader      = "kubeflow-userid"
	defaultUserIDTokenHeader = "kubeflow-userid-token"
	defaultUserIDPrefix      = ""
	defaultUserIDClaim       = "email"
	defaultSessionMaxAge     = "86400"
)

// Issue: https://github.com/gorilla/sessions/issues/200
const secureCookieKeyPair = "notNeededBecauseCookieValueIsRandom"

type server struct {
	provider             *oidc.Provider
	oauth2Config         *oauth2.Config
	store                sessions.Store
	staticDestination    string
	sessionMaxAgeSeconds int
	userIDOpts
	caBundle []byte

	// ZONE: K8s client for creating k8s resources
	kubeclient        *kubernetes.Clientset
	roleBindingLister v1.RoleBindingLister
}

type userIDOpts struct {
	header      string
	tokenHeader string
	prefix      string
	claim       string
}

func main() {

	// Start readiness probe immediately
	log.Infof("Starting readiness probe at %v", defaultHealthServerPort)
	isReady := abool.New()
	go func() {
		log.Fatal(http.ListenAndServe(":"+defaultHealthServerPort, http.HandlerFunc(readiness(isReady))))
	}()

	/////////////
	// Options //
	/////////////

	// OIDC Provider
	providerURL := getURLEnvOrDie("OIDC_PROVIDER")
	authURL := os.Getenv("OIDC_AUTH_URL")
	caBundlePath := os.Getenv("CA_BUNDLE")
	// OIDC Client
	oidcScopes := clean(strings.Split(getEnvOrDie("OIDC_SCOPES"), " "))
	clientID := getEnvOrDie("CLIENT_ID")
	clientSecret := getEnvOrDie("CLIENT_SECRET")
	redirectURL := getURLEnvOrDie("REDIRECT_URL")
	staticDestination := os.Getenv("STATIC_DESTINATION_URL")
	whitelist := clean(strings.Split(os.Getenv("SKIP_AUTH_URI"), " "))
	// UserID Options
	userIDHeader := getEnvOrDefault("USERID_HEADER", defaultUserIDHeader)
	userIDTokenHeader := getEnvOrDefault("USERID_TOKEN_HEADER", defaultUserIDTokenHeader)
	userIDPrefix := getEnvOrDefault("USERID_PREFIX", defaultUserIDPrefix)
	userIDClaim := getEnvOrDefault("USERID_CLAIM", defaultUserIDClaim)
	// Server
	hostname := getEnvOrDefault("SERVER_HOSTNAME", defaultServerHostname)
	port := getEnvOrDefault("SERVER_PORT", defaultServerPort)
	// Store
	storePath := getEnvOrDie("STORE_PATH")
	// Sessions
	sessionMaxAge := getEnvOrDefault("SESSION_MAX_AGE", defaultSessionMaxAge)

	/////////////////////////////////////////////////////
	// Start server immediately for whitelisted routes //
	/////////////////////////////////////////////////////

	s := &server{}

	// Register handlers for routes
	router := mux.NewRouter()
	router.HandleFunc("/authservice/getPassthroughToken", s.getPassthroughToken).Methods(http.MethodGet)
	router.HandleFunc("/login/oidc", s.callback).Methods(http.MethodGet)
	router.HandleFunc("/logout", s.logout).Methods(http.MethodGet)
	router.PathPrefix("/").HandlerFunc(s.authenticate)

	// Start server
	log.Infof("Starting web server at %v:%v", hostname, port)
	stopCh := make(chan struct{})
	go func(stopCh chan struct{}) {
		log.Fatal(http.ListenAndServe(hostname+":"+port, handlers.CORS()(whitelistMiddleware(whitelist, isReady)(router))))
		close(stopCh)
	}(stopCh)

	// Read CA bundle
	var caBundle []byte
	var err error
	if caBundlePath != "" {
		caBundle, err = ioutil.ReadFile(caBundlePath)
		if err != nil {
			log.Fatalf("Could not read CA bundle path %s: %v", caBundlePath, err)
		}
	}

	/////////////////////////////////
	// Resume setup asynchronously //
	/////////////////////////////////

	// OIDC Discovery
	var provider *oidc.Provider
	ctx := setTLSContext(context.Background(), caBundle)
	for {
		provider, err = oidc.NewProvider(ctx, providerURL.String())
		if err == nil {
			break
		}
		log.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	endpoint := provider.Endpoint()
	if authURL != "" {
		endpoint.AuthURL = authURL
	}

	oidcScopes = append(oidcScopes, oidc.ScopeOpenID)

	// Setup Store
	// Using BoltDB by default
	db, err := bolt.Open(storePath, 0666, nil)
	if err != nil {
		log.Fatalf("Error opening bolt store: %v", err)
	}
	defer db.Close()
	// Invoke a reaper which checks and removes expired sessions periodically.
	defer reaper.Quit(reaper.Run(db, reaper.Options{}))
	store, err := store.New(db, store.Config{}, []byte(secureCookieKeyPair))
	if err != nil {
		log.Fatalf("Error creating session store: %v", err)
	}

	// Session Max-Age in seconds
	sessionMaxAgeSeconds, err := strconv.Atoi(sessionMaxAge)
	if err != nil {
		log.Fatalf("Couldn't convert session MaxAge to int: %v", err)
	}

	// Zone: setup the kubernetes client
	restConfig, err := clientconfig.GetConfig()
	kubeclient := kubernetes.NewForConfigOrDie(restConfig)

	// Zone: setup a rolebinding lister to get namespaces from emails
	informerFactory := informers.NewSharedInformerFactory(kubeclient, time.Minute*60)
	roleBindingLister := informerFactory.Rbac().V1().RoleBindings().Lister()
	stop := make(chan struct{})
	informerFactory.Start(stop)
	informerFactory.WaitForCacheSync(stop)

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		provider: provider,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  redirectURL.String(),
			Scopes:       oidcScopes,
		},
		// TODO: Add support for Redis
		store:             store,
		staticDestination: staticDestination,
		userIDOpts: userIDOpts{
			header:      userIDHeader,
			tokenHeader: userIDTokenHeader,
			prefix:      userIDPrefix,
			claim:       userIDClaim,
		},
		sessionMaxAgeSeconds: sessionMaxAgeSeconds,
		caBundle:             caBundle,
		kubeclient:           kubeclient,
		roleBindingLister:    roleBindingLister,
	}

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}
