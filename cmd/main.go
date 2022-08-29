package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func initLogger() *log.Logger {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})

	return logger
}

func main() {
	logger := initLogger()

	parameters := DefaultParametersObject()

	// get command line parameters
	flag.IntVar(&parameters.port, "port", LookupIntEnv("CONFIG_PORT", parameters.port), "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", LookupStringEnv("CONFIG_CERT_PATH", parameters.certFile), "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", LookupStringEnv("CONFIG_KEY_PATH", parameters.keyFile), "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.excludeNamespaces, "excludeNamespaces", LookupStringEnv("CONFIG_EXCLUDE_NAMESPACES", parameters.excludeNamespaces), "Comma-separated namespace names to ignore.")
	flag.StringVar(&parameters.serviceAccounts, "serviceAccounts", LookupStringEnv("CONFIG_SERVICE_ACCOUNTS", parameters.serviceAccounts), "Comma-separated service account names to watch.")
	flag.StringVar(&parameters.targetImagePullSecretName, "targetImagePullSecretName", LookupStringEnv("CONFIG_TARGET_IMAGE_PULL_SECRET_NAME", parameters.targetImagePullSecretName), "Name of the imagePullSecret secret we will create in the namespace of the mutated service account")
	flag.StringVar(&parameters.sourceImagePullSecretName, "sourceImagePullSecretName", LookupStringEnv("CONFIG_SOURCE_IMAGE_PULL_SECRET_NAME", parameters.sourceImagePullSecretName), "Name of the imagePullSecret secret we use as source.")
	flag.StringVar(&parameters.sourceImagePullSecretNamespace, "sourceImagePullSecretNamespace", LookupStringEnv("CONFIG_SOURCE_IMAGE_PULL_SECRET_NAMESPACE", parameters.sourceImagePullSecretNamespace), "Namespace of the imagePullSecret secret we use as source.")
	flag.BoolVar(&parameters.allServiceAccounts, "allServiceAccounts", LookupBoolEnv("CONFIG_ALL_SERVICE_ACCOUNTS", parameters.allServiceAccounts), "Switch for watching all service accounts. If true, serviceAccounts parameter is ignored")
	flag.BoolVar(&parameters.ignoreSecretCreationError, "ignoreSecretCreationError", LookupBoolEnv("CONFIG_IGNORE_SECRET_CREATION_ERROR", parameters.ignoreSecretCreationError), "If true, failed creation/update of secrets in the target namespace will not cause the webhook to fail")
	flag.Parse()

	logger.Infof("Running with config: %+v", parameters)

	whsvr, err := NewWebhookServer(
		&parameters,
		&http.Server{
			Addr: fmt.Sprintf(":%v", parameters.port),
			// This is quite inefficient as it loads file contents on every TLS ClientHello, but ¯\_(ツ)_/¯
			TLSConfig: &tls.Config{GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				logger.Infof("Loading certificates")
				cert, err := tls.LoadX509KeyPair(parameters.certFile, parameters.keyFile)
				return &cert, err
			}},
		},
		logger,
	)
	if err != nil {
		logger.Panicf("Could not create the Webhook server: %v", err)
		logger.Exit(1)
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", whsvr.serve)
	whsvr.server.Handler = mux

	// define the channel for shutting down the main process
	endSignal := make(chan bool, 1)

	// wait for the system interrupts in a separate routine
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-signalChan

		logger.Infof(fmt.Sprintf("Got OS signal \"%+v\", shutting down webhook server gracefully...", sig))

		endSignal <- true
	}()

	// start the webhook server in a separate routine
	go func() {
		if err := whsvr.server.ListenAndServeTLS(parameters.certFile, parameters.keyFile); err != nil {
			logger.Errorf("Failed to listen and serve webhook server: %v", err)
		}

		endSignal <- true
	}()

	<-endSignal
	logger.Infof("Received the end signal, stopping the main process")
	if err := whsvr.Shutdown(); err != nil {
		logger.Errorf("Error while shutting down: %v", err)
	}
}
