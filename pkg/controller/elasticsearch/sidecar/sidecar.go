// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package sidecar

import (
	"file/filepath"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/container"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/settings"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/network"
	corev1 "k8s.io/api/core/v1"
)

const (
	// DefaultHTTPPort is the (default) port used by ApmServer
	DefaultHTTPPort               = 8200
	MetricbeatContainerNamePrefix = "metricbeat"
	// Certificates
	CertificatesDir = "config/elasticsearch-certs"

	APMServerHost        = "apm-server.host"
	APMServerSecretToken = "apm-server.secret_token"

	APMServerSSLEnabled     = "apm-server.ssl.enabled"
	APMServerSSLKey         = "apm-server.ssl.key"
	APMServerSSLCertificate = "apm-server.ssl.certificate"
	SettingsFilename        = "metricbeat.yml"
	SettingsPath            = "/usr/share/metricbeat"

	// Fields

	// currently ES settings are in apis/elasticsearch/v1/fields.go, maybe we should move there?
)

func NewMonitoringSidecars(es esv1.Elasticsearch) []corev1.Container {
	var sidecars []corev1.Container
	if len(es.Spec.Monitoring.ElasticsearchRefs) == 0 {
		return sidecars
	}
	// TODO currently this only builds one sidecar, but it will in the future build one per ElasticsearchRef
	sidecar := corev1.Container{
		Name:  MetricbeatContainerNamePrefix,
		Image: container.ImageRepository(container.BeatsImage, es.Spec.Version),
		Args: []string{
			// log to stdout, this is needed until
			// https://github.com/elastic/beats/issues/6134 is resolved
			// arg reg https://www.elastic.co/guide/en/beats/metricbeat/current/command-line-options.html
			"-e",
		},

		Env: getEnv(es),

		// TODO the volumes are on the pod not the container, so if we want to add it we will also need to modify the WithX func to include it
		VolumeMounts: []corev1.VolumeMount{corev1.VolumeMount{
			// TODO use the namer?
			Name:      fmt.Sprintf("%s-monitoring-config", es.Name),
			ReadOnly:  true,
			MountPath: SettingsPath,
		},
			{
				Name:      es.AssociationConf().GetAuthSecretName(),
				ReadOnly:  true,
				MountPath: SettingsPath,
				// TODO verify this exists
				SubPath: "ca.crt",
			},
		},
	}
	sidecars = append(sidecars, sidecar)
	return sidecars
}

// getEnv returns the default env vars for a metricbeat sidecar
func getEnv(es esv1.Elasticsearch) []corev1.EnvVar {
	return []corev1.EnvVar{
		// TODO make these keys constants?
		{Name: "SRC_ELASTICSEARCH_USERNAME",
			Value: "elastic"},
		{Name: "SRC_ELASTICSEARCH_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						// TODO: create our own monitoring user
						Name: esv1.ElasticUserSecret(es.Name),
					},
					Key: "elastic",
				},
			}},
		{Name: "DEST_ELASTICSEARCH_USERNAME",
			Value: "elastic"},
		{Name: "DEST_ELASTICSEARCH_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: es.AssociationConf().GetAuthSecretName(),
					},
					// TODO see if this is correct
					Key: es.AssociationConf().GetAuthSecretKey(),
				},
			}},
	}
}

// NewSidecarVolumes returns the volumes required to run the sidecars
func NewSidecarVolumes(es esv1.Elasticsearch) []corev1.Volume {
	// TODO is there a nicer guard for this?
	if len(es.Spec.Monitoring.ElasticsearchRefs) == 0 {
		return []corev1.Volume{}
	}

	return []corev1.Volume{
		// TODO use namer
		corev1.Volume{Name: fmt.Sprintf("%s-monitoring-config", es.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-monitoring-config", es.Name),
					},
				}}},
	}
}

// need to update mounts to include both user name
// do we want to allow people to provide a "config" top level like we do for ES etc? i think we do
// i dont think we have the right API as it stands. we probably want one ES reference and the ability to specify the config for it, like we can with ES
// we could theoretically have users override it with env vars in the pod template?
func makeConfig(es esv1.Elasticsearch) *settings.CanonicalConfig {
	srcProtocol := "http"
	if es.Spec.HTTP.TLS.Enabled() {
		srcProtocol = "https"
	}
	// TODO how to reliably get the actual port? do we actually support that easily? I think you would need to update the service too?
	srcURL := fmt.Sprintf("%s://localhost:%d", srcProtocol, network.HTTPPort)

	baseCfg := map[string]interface{}{
		"metricbeat.modules": []map[string]interface{}{
			{
				"module": map[string]interface{}{
					"name": "elasticsearch",
					"metricsets": []string{
						"ccr",
						"cluster_stats",
						"enrich",
						"index",
						"index_recovery",
						"index_summary",
						"ml_job",
						"node_stats",
						"shard",
					},
					"period":        "10s",
					"xpack.enabled": true,
					"hosts":         []string{srcURL},
					"username":      "${SRC_ELASTICSEARCH_USERNAME}",
					"password":      "${SRC_ELASTICSEARCH_PASSWORD}",
					// because we are connecting to localhost the certificate subject will not match, and metricbeat only supports
					// no verification or full verification, not just that the certificate is signed by the CA
					"ssl.verification_mode": "none",
				},
			},
		},
		"output.elasticsearch": map[string]interface{}{
			// TODO can we get the protocol from the association easily? it's not clear to me that we can. i suppose we can just parse the assoc url.
			// we would also want to update the verification mode
			"protocol": "https",
			"hosts":    []string{es.AssociationConf().GetURL()},
			"username": "${DEST_ELASTICSEARCH_USERNAME}",
			"password": "${DEST_ELASTICSEARCH_PASSWORD}",
			// TODO move this to a package level var?
			"ssl.certificate_authorities": []string{filepath.Join(SettingsPath, "ca.crt")},
			// since the remote certificate might be user provided, it may not have a subject name that matches the internal host name
			"ssl.verification_mode": "certificate",
		},
	}

	return settings.MustCanonicalConfig(baseCfg)
}
