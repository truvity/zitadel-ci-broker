{{- define "zitadel-ci-broker.labels" -}}
app.kubernetes.io/name: zitadel-ci-broker
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
