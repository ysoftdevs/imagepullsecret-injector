package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/api/errors"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

type WebhookServer struct {
	server *http.Server
	config *WhSvrParameters
	client *kubernetes.Clientset
}

// WhSvrParameters represents all configuration options available though cmd parameters or env variables
type WhSvrParameters struct {
	port                           int
	certFile                       string
	keyFile                        string
	excludeNamespaces              string
	serviceAccounts                string
	allServiceAccounts             bool
	targetImagePullSecretName      string
	sourceImagePullSecretName      string
	sourceImagePullSecretNamespace string
	ignoreSecretCreationError      bool
}

var (
	defaultIgnoredNamespaces = []string{
		metav1.NamespaceSystem,
		metav1.NamespacePublic,
	}

	defaultServiceAccounts = []string{
		"default",
	}
)

// NewWebhookServer constructor for WebhookServer
func NewWebhookServer(parameters *WhSvrParameters, server *http.Server) (*WebhookServer, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		glog.Errorf("Could not create k8s client: %v", err)
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Errorf("Could not create k8s clientset: %v", err)
		return nil, err
	}

	return &WebhookServer{
		config: parameters,
		server: server,
		client: clientset,
	}, nil

}

// DefaultParametersObject returns a parameters object with the default values
func DefaultParametersObject() WhSvrParameters {
	return WhSvrParameters{
		port:                           8443,
		certFile:                       "/etc/webhook/certs/cert.pem",
		keyFile:                        "/etc/webhook/certs/key.pem",
		excludeNamespaces:              strings.Join(defaultIgnoredNamespaces, ","),
		serviceAccounts:                strings.Join(defaultServiceAccounts, ","),
		allServiceAccounts:             false,
		targetImagePullSecretName:      "my-cool-secret",
		sourceImagePullSecretName:      "my-cool-secret-source",
		sourceImagePullSecretNamespace: "default",
		ignoreSecretCreationError:      false,
	}
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

func addImagePullSecret(target, added []corev1.LocalObjectReference, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.LocalObjectReference{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

// ensureSecrets looks up the source secret and makes sure the namespace the patched SA is in contains it too
func (whsvr *WebhookServer) ensureSecrets(ar *v1beta1.AdmissionReview) error {
	glog.Infof("Ensuring existing secrets")
	targetNamespace := ar.Request.Namespace

	currentNamespace := getCurrentNamespace()

	glog.Infof("Looking for the source secret")
	sourceSecret, err := whsvr.client.CoreV1().Secrets(whsvr.config.sourceImagePullSecretNamespace).Get(whsvr.config.sourceImagePullSecretName, metav1.GetOptions{})
	if err != nil {
		glog.Errorf("Could not fetch source secret %s in namespace %s: %v", whsvr.config.sourceImagePullSecretName, currentNamespace, err)
		return err
	}
	if sourceSecret.Type != corev1.SecretTypeDockerConfigJson {
		err := fmt.Errorf("source secret %s in namespace %s exists, but has incorrect type (is %s, should be %s)", whsvr.config.sourceImagePullSecretName, currentNamespace, sourceSecret.Type, corev1.SecretTypeDockerConfigJson)
		glog.Errorf("%v", err)
		return err
	}
	glog.Infof("Source secret found")

	glog.Infof("Looking for the existing target secret")
	secret, err := whsvr.client.CoreV1().Secrets(targetNamespace).Get(whsvr.config.targetImagePullSecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		glog.Errorf("Could not fetch secret %s in namespace %s: %v", whsvr.config.targetImagePullSecretName, targetNamespace, err)
		return err
	}

	if err != nil && errors.IsNotFound(err) {
		glog.Infof("Target secret not found, creating a new one")
		if _, createErr := whsvr.client.CoreV1().Secrets(targetNamespace).Create(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      whsvr.config.targetImagePullSecretName,
				Namespace: targetNamespace,
			},
			Data: sourceSecret.Data,
			Type: sourceSecret.Type,
		}); createErr != nil {
			glog.Errorf("Could not create secret %s in namespace %s: %v", whsvr.config.targetImagePullSecretName, targetNamespace, err)
			return err
		}
		glog.Infof("Target secret created successfully")
		return nil
	}

	glog.Infof("Target secret found, updating")
	secret.Data = sourceSecret.Data
	if _, err := whsvr.client.CoreV1().Secrets(targetNamespace).Update(secret); err != nil {
		glog.Errorf("Could not update secret %s in namespace %s: %v", whsvr.config.targetImagePullSecretName, targetNamespace, err)
		return err
	}
	glog.Infof("Target secret updated successfully")

	return nil
}

// shouldMutate goes through all filters and determines whether the incoming SA matches them
func (whsvr *WebhookServer) shouldMutate(sa corev1.ServiceAccount) bool {
	for _, excludedNamespace := range strings.Split(whsvr.config.excludeNamespaces, ",") {
		if sa.Namespace == excludedNamespace {
			return false
		}
	}

	if whsvr.config.allServiceAccounts {
		return true
	}

	for _, saName := range strings.Split(whsvr.config.serviceAccounts, ",") {
		if saName == sa.Name {
			return true
		}
	}

	return false
}

// mutateServiceAccount contains the whole mutation logic
func (whsvr *WebhookServer) mutateServiceAccount(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	glog.Infof("Unmarshalling the ServiceAccount object from request")
	var sa corev1.ServiceAccount
	if err := json.Unmarshal(req.Object.Raw, &sa); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, sa.Name, req.UID, req.Operation, req.UserInfo)

	if !whsvr.shouldMutate(sa) {
		glog.Infof("Conditions for mutation not met, skipping")
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	// Check whether we already have the imagePullSecretName present
	if sa.ImagePullSecrets != nil {
		glog.Infof("ServiceAccount is already in the correct state, skipping")
		for _, lor := range sa.ImagePullSecrets {
			if whsvr.config.targetImagePullSecretName == lor.Name {
				return &v1beta1.AdmissionResponse{
					Allowed: true,
				}
			}
		}
	}

	glog.Infof("ServiceAccount is missing ImagePullSecrets configuration, creating a patch")

	var patch []patchOperation
	patch = append(patch, addImagePullSecret(sa.ImagePullSecrets, []corev1.LocalObjectReference{{Name: whsvr.config.targetImagePullSecretName}}, "/imagePullSecrets")...)
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		glog.Errorf("Could not marshal patch object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	if err := whsvr.ensureSecrets(ar); err != nil {
		glog.Errorf("Could not ensure existence of the imagePullSecret")
		if !whsvr.config.ignoreSecretCreationError {
			glog.Errorf("Failing the mutation process")
			return &v1beta1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
		glog.Infof("ignoreSecretCreationError is true, ignoring")
	}

	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func parseIncomingRequest(r *http.Request) (v1beta1.AdmissionReview, *errors.StatusError) {
	var ar v1beta1.AdmissionReview
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("Empty body")
		return ar, errors.NewBadRequest("Empty body")
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		err := &errors.StatusError{ErrStatus: metav1.Status{
			Status:  metav1.StatusFailure,
			Message: fmt.Sprintf("Content-Type=%s, expect application/json", contentType),
			Reason:  metav1.StatusReasonUnsupportedMediaType,
			Code:    http.StatusUnsupportedMediaType,
		}}
		return ar, err
	}

	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Error("Could not parse the request body")
		return ar, errors.NewBadRequest(fmt.Sprintf("Could not parse the request body: %+v", err))
	}

	return ar, nil
}

func (whsvr *WebhookServer) sendResponse(w http.ResponseWriter, admissionReview v1beta1.AdmissionReview) error {
	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return err
	}
	glog.Infof("Writing response")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		return err
	}

	return nil
}

// serve parses the raw incoming request, calls the mutation logic and sends the proper response
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	admissionReviewIn, statusErr := parseIncomingRequest(r)
	if statusErr != nil {
		http.Error(w, statusErr.ErrStatus.Message, int(statusErr.ErrStatus.Code))
		return
	}

	admissionResponse := whsvr.mutateServiceAccount(&admissionReviewIn)

	admissionReviewOut := v1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
	}
	if admissionResponse != nil {
		admissionReviewOut.Response = admissionResponse
		if admissionReviewIn.Request != nil {
			admissionReviewOut.Response.UID = admissionReviewIn.Request.UID
		}
	}

	if err := whsvr.sendResponse(w, admissionReviewOut); err != nil {
		glog.Errorf("Could not send response %v", err)
	}
}
