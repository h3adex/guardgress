{{/*
Expand the name of the chart.
*/}}
{{- define "guardgress.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "guardgress.fullname" -}}
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
{{- define "guardgress.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "guardgress.labels" -}}
helm.sh/chart: {{ include "guardgress.chart" . }}
{{ include "guardgress.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "guardgress.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guardgress.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "guardgress.serviceAccountName" -}}
{{- default (include "guardgress.fullname" .) .Values.serviceAccount.name }}
{{- end }}

{{/*
Create the name of the cluster-role-binding to use
*/}}
{{- define "guardgress.clusterRoleBindingName" -}}
{{- printf "%s-%s" .Chart.Name "cr-binding" | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name of the clusterrole to use
*/}}
{{- define "guardgress.clusterRole" -}}
{{- printf "%s-%s" .Chart.Name "cr" | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}