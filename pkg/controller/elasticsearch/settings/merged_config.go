// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package settings

import (
	"fmt"
	"path"

	commonv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/certificates"
	common "github.com/elastic/cloud-on-k8s/pkg/controller/common/settings"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/version"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/client"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/volume"
)

// NewMergedESConfig merges user provided Elasticsearch configuration with configuration derived from the given
// parameters. The user provided config overrides have precedence over the ECK config.
func NewMergedESConfig(
	clusterName string,
	ver version.Version,
	httpConfig commonv1.HTTPConfig,
	userConfig commonv1.Config,
) (CanonicalConfig, error) {
	userCfg, err := common.NewCanonicalConfigFrom(userConfig.Data)
	if err != nil {
		return CanonicalConfig{}, err
	}
	config := baseConfig(clusterName, ver).CanonicalConfig
	err = config.MergeWith(
		xpackConfig(ver, httpConfig).CanonicalConfig,
		userCfg,
	)
	if err != nil {
		return CanonicalConfig{}, err
	}
	return CanonicalConfig{config}, nil
}

// baseConfig returns the base ES configuration to apply for the given cluster
func baseConfig(clusterName string, ver version.Version) *CanonicalConfig {
	cfg := map[string]interface{}{
		// derive node name dynamically from the pod name, injected as env var
		esv1.NodeName:    "${" + EnvPodName + "}",
		esv1.ClusterName: clusterName,
		// https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html
		// derive IP dynamically from the pod IP, injected as env var
		// esv1.NetworkPublishHost: "${" + EnvPodIP + "}",
		// esv1.NetworkHost: "0.0.0.0",
		esv1.NetworkHost: "0.0.0.0",
		// TODO make sure this is actually what forces it to use it for transport
		// this also generates a ton of these deprecation warnings, even though we do not set the mentioned jvm option
		// {"type": "deprecation", "timestamp": "2020-04-07T20:31:08,555Z", "level": "WARN", "component": "o.e.d.t.TransportInfo", "cluster.name": "elasticsearch-sample", "node.name": "elasticsearch-sample-es-default-2", "message": "transport.publish_address was printed as [ip:port] instead of [hostname/ip:port]. This format is deprecated and will change to [hostname/ip:port] in a future version. Use -Des.transport.cname_in_publish_address=true to enforce non-deprecated formatting.", "cluster.uuid": "gN0gQdteSzKYoEICZa4ASA", "node.id": "40o6w2xgSu-neHyJ_Om9aQ"  }
		// this says it was fixed https://github.com/elastic/elasticsearch/issues/47436, but i can repro on 7.6.2
		esv1.NetworkPublishHost: fmt.Sprintf("${%s}.${%s}", EnvPodName, HeadlessServiceName),
		esv1.PathLogs:           volume.ElasticsearchLogsMountPath,
	}

	// seed hosts setting name changed starting ES 7.X
	fileProvider := "file"
	if ver.Major < 7 {
		cfg[esv1.DiscoveryZenHostsProvider] = fileProvider
	} else {
		cfg[esv1.DiscoverySeedProviders] = fileProvider
	}

	return &CanonicalConfig{common.MustCanonicalConfig(cfg)}
}

// xpackConfig returns the configuration bit related to XPack settings
func xpackConfig(ver version.Version, httpCfg commonv1.HTTPConfig) *CanonicalConfig {
	// enable x-pack security, including TLS
	cfg := map[string]interface{}{
		// x-pack security general settings
		esv1.XPackSecurityEnabled:                      "true",
		esv1.XPackSecurityAuthcReservedRealmEnabled:    "false",
		esv1.XPackSecurityTransportSslVerificationMode: "full",

		// x-pack security http settings
		esv1.XPackSecurityHttpSslEnabled:     httpCfg.TLS.Enabled(),
		esv1.XPackSecurityHttpSslKey:         path.Join(volume.HTTPCertificatesSecretVolumeMountPath, certificates.KeyFileName),
		esv1.XPackSecurityHttpSslCertificate: path.Join(volume.HTTPCertificatesSecretVolumeMountPath, certificates.CertFileName),

		// x-pack security transport settings
		esv1.XPackSecurityTransportSslEnabled: "true",
		esv1.XPackSecurityTransportSslKey: path.Join(
			volume.ConfigVolumeMountPath,
			volume.NodeTransportCertificatePathSegment,
			volume.NodeTransportCertificateKeyFile,
		),
		esv1.XPackSecurityTransportSslCertificate: path.Join(
			volume.ConfigVolumeMountPath,
			volume.NodeTransportCertificatePathSegment,
			volume.NodeTransportCertificateCertFile,
		),
		esv1.XPackSecurityTransportSslCertificateAuthorities: []string{
			path.Join(volume.TransportCertificatesSecretVolumeMountPath, certificates.CAFileName),
			path.Join(volume.RemoteCertificateAuthoritiesSecretVolumeMountPath, certificates.CAFileName),
		},
		esv1.XPackSecurityHttpSslCertificateAuthorities: path.Join(volume.HTTPCertificatesSecretVolumeMountPath, certificates.CAFileName),
	}

	// always enable the built-in file and native internal realms for user auth, ordered as first
	if ver.Major < 7 {
		// 6.x syntax
		cfg[esv1.XPackSecurityAuthcRealmsFile1Type] = "file"
		cfg[esv1.XPackSecurityAuthcRealmsFile1Order] = -100
		cfg[esv1.XPackSecurityAuthcRealmsNative1Type] = "native"
		cfg[esv1.XPackSecurityAuthcRealmsNative1Order] = -99
	} else {
		// 7.x syntax
		cfg[esv1.XPackSecurityAuthcRealmsFileFile1Order] = -100
		cfg[esv1.XPackSecurityAuthcRealmsNativeNative1Order] = -99
	}

	if ver.IsSameOrAfter(version.MustParse("7.6.0")) {
		cfg[esv1.XPackLicenseUploadTypes] = []string{
			string(client.ElasticsearchLicenseTypeTrial), string(client.ElasticsearchLicenseTypeEnterprise),
		}
	}

	return &CanonicalConfig{common.MustCanonicalConfig(cfg)}
}
