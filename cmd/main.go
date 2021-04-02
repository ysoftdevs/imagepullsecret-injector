package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/golang/glog"
)

func LookupStringEnv(envName string, defVal string) string {
	if envVal, exists := os.LookupEnv(envName); exists {
		return envVal
	}

	return defVal
}

func LookupBoolEnv(envName string, defVal bool) bool {
	if envVal, exists := os.LookupEnv(envName); exists {
		if boolVal, err := strconv.ParseBool(envVal); err == nil {
			return boolVal
		}
	}

	return defVal
}

func LookupIntEnv(envName string, defVal int) int {
	if envVal, exists := os.LookupEnv(envName); exists {
		if intVal, err := strconv.Atoi(envVal); err == nil {
			return intVal
		}
	}

	return defVal
}

func main() {
	parameters := DefaultParametersObject()

	// get command line parameters
	flag.IntVar(&parameters.port, "port", LookupIntEnv("CONFIG_PORT", parameters.port), "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", LookupStringEnv("CONFIG_CERT_PATH", parameters.certFile), "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", LookupStringEnv("CONFIG_KEY_PATH", parameters.keyFile), "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.excludeNamespaces, "excludeNamespaces", LookupStringEnv("CONFIG_EXCLUDE_NAMESPACES", parameters.excludeNamespaces), "Comma-separated namespace names to ignore.")
	flag.StringVar(&parameters.serviceAccounts, "serviceAccounts", LookupStringEnv("CONFIG_SERVICE_ACCOUNTS", parameters.serviceAccounts), "Comma-separated service account names to watch.")
	flag.StringVar(&parameters.sourceImagePullSecretName, "sourceImagePullSecretName", LookupStringEnv("CONFIG_SOURCE_IMAGE_PULL_SECRET_NAME", parameters.sourceImagePullSecretName), "Name of the imagePullSecret secret we use as source.")
	flag.StringVar(&parameters.sourceImagePullSecretNamespace, "sourceImagePullSecretNamespace", LookupStringEnv("CONFIG_SOURCE_IMAGE_PULL_SECRET_NAMESPACE", parameters.sourceImagePullSecretNamespace), "Namespace of the imagePullSecret secret we use as source.")
	flag.BoolVar(&parameters.allServiceAccounts, "allServiceAccounts", LookupBoolEnv("CONFIG_ALL_SERVICE_ACCOUNTS", parameters.allServiceAccounts), "Switch for watching all service accounts. If true, serviceAccounts parameter is ignored")
	flag.Parse()

	glog.Infof("Running with config: %+v", parameters)

	//sidecarConfig, err := loadConfig(parameters.sidecarCfgFile)
	//if err != nil {
	//	glog.Errorf("Failed to load configuration: %v", err)
	//}

	pair, err := tls.LoadX509KeyPair(parameters.certFile, parameters.keyFile)
	if err != nil {
		glog.Errorf("Failed to load key pair: %v", err)
	}

	whsvr := &WebhookServer{
		config: &parameters,
		server: &http.Server{
			Addr:      fmt.Sprintf(":%v", parameters.port),
			// TODO: rewrite using GetCertificate
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", whsvr.serve)
	whsvr.server.Handler = mux

	// start webhook server in new rountine
	go func() {
		if err := whsvr.server.ListenAndServeTLS(parameters.certFile, parameters.keyFile); err != nil {
			glog.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	glog.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	if err := whsvr.server.Shutdown(context.Background()); err != nil {
		glog.Errorf("Error while shutting down: %v", err)
	}
}
