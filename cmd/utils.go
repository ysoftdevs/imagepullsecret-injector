package main

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// LookupStringEnv either returns the the value of the env variable, or the provided default value, if the env doesn't exist
func LookupStringEnv(envName string, defVal string) string {
	if envVal, exists := os.LookupEnv(envName); exists {
		return envVal
	}

	return defVal
}

// LookupBoolEnv either returns the the value of the env variable, or the provided default value, if the env doesn't exist
func LookupBoolEnv(envName string, defVal bool) bool {
	if envVal, exists := os.LookupEnv(envName); exists {
		if boolVal, err := strconv.ParseBool(envVal); err == nil {
			return boolVal
		}
	}

	return defVal
}

// LookupIntEnv either returns the the value of the env variable, or the provided default value, if the env doesn't exist
func LookupIntEnv(envName string, defVal int) int {
	if envVal, exists := os.LookupEnv(envName); exists {
		if intVal, err := strconv.Atoi(envVal); err == nil {
			return intVal
		}
	}

	return defVal
}

func getCurrentNamespace() string {
	// Check whether we have overridden the namespace
	if ns, ok := os.LookupEnv("POD_NAMESPACE"); ok {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available (this should exist if running in a K8S pod)
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}
