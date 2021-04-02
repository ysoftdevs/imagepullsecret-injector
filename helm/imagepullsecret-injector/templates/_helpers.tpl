{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "imagepullsecret-injector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "imagepullsecret-injector.serviceName" -}}
ips-injector-svc
{{- end }}

{{- define "imagepullsecret-injector.lookupCaBundle" -}}
{{- /* Find the name of the secret corresponding to the default SA in the default namespace */ -}}
{{- /* Equivalent to `kubectl get sa -n default default -ojsonpath='{.secrets[0].name}'` */ -}}
{{- $defaultSecretName := ((lookup "v1" "ServiceAccount" "default" "default").secrets | first).name -}}
{{- /* Fetch the ca.crt from the default secret (still base64-encoded)*/ -}}
{{- /* Equivalent to `kubectl get secret -n default $defaultSecretName -ojsonpath='{.data.ca\.crt}'` */ -}}
{{- $caBundle := get (lookup "v1" "Secret" "default" $defaultSecretName ).data "ca.crt" -}}
{{- $caBundle -}}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "imagepullsecret-injector.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "imagepullsecret-injector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "imagepullsecret-injector.labels" -}}
helm.sh/chart: {{ include "imagepullsecret-injector.chart" . }}
{{ include "imagepullsecret-injector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "imagepullsecret-injector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "imagepullsecret-injector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "imagepullsecret-injector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "imagepullsecret-injector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
