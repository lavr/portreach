{{/*
Expand the name of the chart.
*/}}
{{- define "portreach.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "portreach.fullname" -}}
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
{{- define "portreach.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "portreach.labels" -}}
helm.sh/chart: {{ include "portreach.chart" . }}
app.kubernetes.io/part-of: {{ include "portreach.name" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
UI component selector labels.
*/}}
{{- define "portreach.ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end }}

{{/*
Agent component selector labels.
*/}}
{{- define "portreach.agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portreach.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
UI resource name.
*/}}
{{- define "portreach.ui.fullname" -}}
{{- printf "%s-ui" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Agent resource name.
*/}}
{{- define "portreach.agent.fullname" -}}
{{- printf "%s-agent" (include "portreach.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Headless agent service FQDN, used by the UI for DNS discovery.
*/}}
{{- define "portreach.agent.dnsName" -}}
{{- printf "%s.%s.svc.%s" (include "portreach.agent.fullname" .) .Release.Namespace .Values.clusterDomain }}
{{- end }}

{{/*
The image tag, defaulting to <appVersion>-rootless.
*/}}
{{- define "portreach.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default (printf "%s-rootless" .Chart.AppVersion)) }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "portreach.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "portreach.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
