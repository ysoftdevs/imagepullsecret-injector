# Kubernetes Mutating Webhook for ImagePullSecret injection in ServiceAccounts

The responsibility of this webhook is to patch all newly created/updated service account and make sure they all contained proper imagepullsecret configuration. 

This repo produces one helm chart available via helm repository https://ysoftdevs.github.io/imagepullsecret-injector. There are also 2 docker images:
- `ghcr.io/ysoftdevs/imagepullsecret-injector/imagepullsecret-injector` - the image containing the webhook itself
- `ghcr.io/ysoftdevs/imagepullsecret-injector/webhook-cert-generator` - helper image responsible for (re)generating the certificates

## Helm description
The helm chart consists of 2 parts: the certificate generator and the webhook configuration itself.

Certificate generation part periodically generates certificates signed by kubernetes' CA and passes them to the webhook where they are used as server-side certificates. The flow works roughly like this:
1. We generate a CSR using openssl and tie the certificate to the webhook's service DNS.
1. We create a k8s CertificateSigningRequest from the openssl CSR.
1. We approve this request using our special ServiceAccount with approve permissions. This makes kubernetes issue the certificate
1. We fetch the certificate from the k8s CSR (at `.status.certificate`) and create a secret from it
1. We also create a CronJob that does this periodically as k8s only issues certificates for 1 year

The main part is the deployment and the web hook configuration. The flow is as follows
1. The MutatingWebhookConfiguration we create instructs k8s to pass all requests for creating/updating all ServiceAccounts to our webhook before finishing the request
1. We check whether the SA has the correctly defined imagepullsecret configuration. if not, we create a patch for the resource
1. We also check whether we have the secret we are using in the imagepullsecret in the SA's namespace. If not, we create it based on our source secret
1. We return the patch to k8s, which applies the changes

Of note is also a fact that the chart runs a lookup to the connected cluster to fetch the CA bundle for the MutatingWebhook. This means `helm template` won't work.

## Running locally
1. Create the prerequisite resources:
    ```bash
    kubectl create ns imagepullsecret-injector

    kubectl create secret -n imagepullsecret-injector \
        generic acr-dockerconfigjson-source \
        --type=kubernetes.io/dockerconfigjson \
        --from-literal=.dockerconfigjson='<your .dockerconfigjson configuration file>'
    ```

1. Build the images and run the chart
    ``` bash
    make build-image
    helm upgrade -i imagepullsecret-injector \
        -n imagepullsecret-injector \
        charts/imagepullsecret-injector
    ```
    Alternatively, you can use the pre-built, publicly available helm chart and docker images:
    ```bash
    helm repo add imagepullsecret-injector https://ysoftdevs.github.io/imagepullsecret-injector
    helm repo update
    helm upgrade -i imagepullsecret-injector \
        -n imagepullsecret-injector \
        magepullsecret-injector/imagepullsecret-injector
    ```

1. To test whether everything works, you can run
    ```bash
    kubectl create ns yolo
    kubectl get sa -n yolo default -ojsonpath='{.imagePullSecrets}'
    ```
    The `get` command should display _some_ non-empty result.

## Releasing locally
To authenticate to the docker registry to push the images manually, you will need your own Github Personal Access Token. For more information follow this guide https://docs.github.com/en/packages/guides/migrating-to-github-container-registry-for-docker-images#authenticating-with-the-container-registry