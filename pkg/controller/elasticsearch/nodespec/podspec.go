// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package nodespec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"go.elastic.co/apm"
	corev1 "k8s.io/api/core/v1"

	commonv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/association"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/certificates"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/container"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/defaults"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/hash"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/keystore"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/tracing"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/version"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/volume"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/initcontainer"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/label"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/network"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/settings"
	esvolume "github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/volume"
	"github.com/elastic/cloud-on-k8s/pkg/utils/k8s"
)

// BuildPodTemplateSpec builds a new PodTemplateSpec for an Elasticsearch node.
func BuildPodTemplateSpec(
	es esv1.Elasticsearch,
	nodeSet esv1.NodeSet,
	cfg settings.CanonicalConfig,
	keystoreResources *keystore.Resources,
) (corev1.PodTemplateSpec, error) {
	volumes, volumeMounts := buildVolumes(es.Name, nodeSet, keystoreResources)
	labels, err := buildLabels(es, cfg, nodeSet, keystoreResources)
	if err != nil {
		return corev1.PodTemplateSpec{}, err
	}

	builder := defaults.NewPodTemplateBuilder(nodeSet.PodTemplate, esv1.ElasticsearchContainerName).
		WithDockerImage(es.Spec.Image, container.ImageRepository(container.ElasticsearchImage, es.Spec.Version))

	initContainers, err := initcontainer.NewInitContainers(
		builder.Container.Image,
		transportCertificatesVolume(es.Name),
		es.Name,
		keystoreResources,
	)
	if err != nil {
		return corev1.PodTemplateSpec{}, err
	}

	sidecars, err := getSidecars(es)
	defaultContainerPorts := getDefaultContainerPorts(es)

	builder = builder.
		WithResources(DefaultResources).
		WithTerminationGracePeriod(DefaultTerminationGracePeriodSeconds).
		WithPorts(defaultContainerPorts).
		WithReadinessProbe(*NewReadinessProbe()).
		WithAffinity(DefaultAffinity(es.Name)).
		WithEnv(DefaultEnvVars(es.Spec.HTTP, HeadlessServiceName(esv1.StatefulSet(es.Name, nodeSet.Name)))...).
		WithVolumes(volumes...).
		WithVolumeMounts(volumeMounts...).
		WithLabels(labels).
		WithAnnotations(DefaultAnnotations).
		WithInitContainers(initContainers...).
		WithContainers(sidecars...).
		WithPreStopHook(*NewPreStopHook()).
		WithInitContainerDefaults()

	return builder.PodTemplate, nil
}

func getDefaultContainerPorts(es esv1.Elasticsearch) []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{Name: es.Spec.HTTP.Protocol(), ContainerPort: network.HTTPPort, Protocol: corev1.ProtocolTCP},
		{Name: "transport", ContainerPort: network.TransportPort, Protocol: corev1.ProtocolTCP},
	}
}

func transportCertificatesVolume(esName string) volume.SecretVolume {
	return volume.NewSecretVolumeWithMountPath(
		esv1.TransportCertificatesSecret(esName),
		esvolume.TransportCertificatesSecretVolumeName,
		esvolume.TransportCertificatesSecretVolumeMountPath,
	)
}

func buildLabels(
	es esv1.Elasticsearch,
	cfg settings.CanonicalConfig,
	nodeSet esv1.NodeSet,
	keystoreResources *keystore.Resources,
) (map[string]string, error) {
	// label with a hash of the config to rotate the pod on config changes
	unpackedCfg, err := cfg.Unpack()
	if err != nil {
		return nil, err
	}
	nodeRoles := unpackedCfg.Node
	cfgHash := hash.HashObject(cfg)

	// label with version
	ver, err := version.Parse(es.Spec.Version)
	if err != nil {
		return nil, err
	}

	podLabels, err := label.NewPodLabels(
		k8s.ExtractNamespacedName(&es),
		esv1.StatefulSet(es.Name, nodeSet.Name),
		*ver, nodeRoles, cfgHash, es.Spec.HTTP.Protocol(),
	)
	if err != nil {
		return nil, err
	}

	if keystoreResources != nil {
		// label with a checksum of the secure settings to rotate the pod on secure settings change
		// TODO: use hash.HashObject instead && fix the config checksum label name?
		configChecksum := sha256.New224()
		_, _ = configChecksum.Write([]byte(keystoreResources.Version))
		podLabels[label.SecureSettingsHashLabelName] = fmt.Sprintf("%x", configChecksum.Sum(nil))
	}

	return podLabels, nil
}

func getSidecars(es esv1.Elasticsearch) ([]corev1.Container, error) {
	var sidecars []corev1.Container
	for _, monClus := range es.Spec.Monitoring.ElasticsearchRefs {
		//
		sidecars = append(sidecars, buildSidecar(monClus))
	}
	return sidecars, nil
}

func buildSidecar(esRef esv1.ElasticsearchRef) corev1.Container {
	return corev1.Container{}
}

func NewConfigFromSpec(c k8s.Client, as *apmv1.ApmServer) (*settings.CanonicalConfig, error) {
	specConfig := as.Spec.Config
	if specConfig == nil {
		specConfig = &commonv1.Config{}
	}

	userSettings, err := settings.NewCanonicalConfigFrom(specConfig.Data)
	if err != nil {
		return nil, err
	}

	outputCfg := settings.NewCanonicalConfig()
	if as.AssociationConf().IsConfigured() {
		// Get username and password
		username, password, err := association.ElasticsearchAuthSettings(c, as)
		if err != nil {
			return nil, err
		}

		tmpOutputCfg := map[string]interface{}{
			"output.elasticsearch.hosts":    []string{as.AssociationConf().GetURL()},
			"output.elasticsearch.username": username,
			"output.elasticsearch.password": password,
		}
		if as.AssociationConf().GetCACertProvided() {
			tmpOutputCfg["output.elasticsearch.ssl.certificate_authorities"] = []string{filepath.Join(CertificatesDir, certificates.CAFileName)}
		}

		outputCfg = settings.MustCanonicalConfig(tmpOutputCfg)
	}

	// Create a base configuration.

	cfg := settings.MustCanonicalConfig(map[string]interface{}{
		APMServerHost:        fmt.Sprintf(":%d", DefaultHTTPPort),
		APMServerSecretToken: "${SECRET_TOKEN}",
	})

	// Merge the configuration with userSettings last so they take precedence.
	err = cfg.MergeWith(
		outputCfg,
		settings.MustCanonicalConfig(tlsSettings(as)),
		userSettings,
	)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// CanonicalConfig contains configuration for Kibana ("kibana.yml"),
// as a hierarchical key-value configuration.
type CanonicalConfig struct {
	*settings.CanonicalConfig
}

// NewConfigSettings returns the Kibana configuration settings for the given Kibana resource.
func NewConfigSettings(ctx context.Context, client k8s.Client, kb kbv1.Kibana, v version.Version) (CanonicalConfig, error) {
	span, _ := apm.StartSpan(ctx, "new_config_settings", tracing.SpanTypeApp)
	defer span.End()

	currentConfig, err := getExistingConfig(client, kb)
	if err != nil {
		return CanonicalConfig{}, err
	}

	filteredCurrCfg, err := filterExistingConfig(currentConfig)
	if err != nil {
		return CanonicalConfig{}, err
	}

	specConfig := kb.Spec.Config
	if specConfig == nil {
		specConfig = &commonv1.Config{}
	}

	userSettings, err := settings.NewCanonicalConfigFrom(specConfig.Data)
	if err != nil {
		return CanonicalConfig{}, err
	}

	cfg := settings.MustCanonicalConfig(baseSettings(&kb))
	kibanaTLSCfg := settings.MustCanonicalConfig(kibanaTLSSettings(kb))
	versionSpecificCfg := VersionDefaults(&kb, v)

	if !kb.RequiresAssociation() {
		// merge the configuration with userSettings last so they take precedence
		if err := cfg.MergeWith(
			filteredCurrCfg,
			versionSpecificCfg,
			kibanaTLSCfg,
			userSettings); err != nil {
			return CanonicalConfig{}, err
		}
		return CanonicalConfig{cfg}, nil
	}

	username, password, err := association.ElasticsearchAuthSettings(client, &kb)
	if err != nil {
		return CanonicalConfig{}, err
	}

	// merge the configuration with userSettings last so they take precedence
	err = cfg.MergeWith(
		filteredCurrCfg,
		versionSpecificCfg,
		kibanaTLSCfg,
		settings.MustCanonicalConfig(elasticsearchTLSSettings(kb)),
		settings.MustCanonicalConfig(
			map[string]interface{}{
				ElasticsearchUsername: username,
				ElasticsearchPassword: password,
			},
		),
		userSettings,
	)
	if err != nil {
		return CanonicalConfig{}, err
	}

	return CanonicalConfig{cfg}, nil
}
