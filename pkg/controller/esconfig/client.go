// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esconfig

import (
	"crypto/x509"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/certificates"
	version "github.com/elastic/cloud-on-k8s/pkg/controller/common/version"
	esclient "github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/client"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/services"
	"github.com/elastic/cloud-on-k8s/pkg/controller/elasticsearch/user"
	"github.com/elastic/cloud-on-k8s/pkg/utils/k8s"
	"github.com/elastic/cloud-on-k8s/pkg/utils/net"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func NewESClient(dialer net.Dialer, k8sclient k8s.Client, es esv1.Elasticsearch) (esclient.Client, error) {
	var client esclient.Client
	// TODO need to qualify this with namespace before adding port
	// currently adds
	// 2020-09-08T18:26:26.096-0500	ERROR	controller	Reconciler error	{"service.version": "1.3.0-SNAPSHOT+5d743c5c", "controller": "esconfig-controller", "name": "quickstart-config", "namespace": "default", "error": "parse \"https://quickstart-es-http.default.svc:9200.default/_snapshot/my_repository\": invalid port \":9200.default\" after host"}
	url := services.ExternalServiceURL(es)
	ver, err := version.Parse(es.Spec.Version)
	if err != nil {
		return client, err
	}

	creds, err := GetElasticsearchUser(k8sclient, es)
	if err != nil {
		return client, err
	}
	// maybe look to see how we get this in the association?
	caCerts, err := GetElasticsearchCA(k8sclient, es)
	if err != nil {
		return client, err
	}
	client = esclient.NewElasticsearchClient(dialer, url, creds, *ver, caCerts)
	return client, err
}

func GetElasticsearchUser(k8sclient k8s.Client, es esv1.Elasticsearch) (esclient.BasicAuth, error) {
	// get this out of the secret?
	var creds esclient.BasicAuth
	secretName := esv1.InternalUsersSecret(es.Name)
	var secret corev1.Secret
	nsn := types.NamespacedName{
		Name:      secretName,
		Namespace: es.Namespace,
	}
	err := k8sclient.Get(nsn, &secret)
	if err != nil {
		return creds, err
	}

	password := secret.Data[user.ControllerUserName]
	if len(password) == 0 {
		return creds, fmt.Errorf("internal user secret %s is missing credentials for user %s", secretName, user.ControllerUserName)
	}

	// driver gets this out of ReconcileUsersAndRoles
	return esclient.BasicAuth{
		Name:     user.ControllerUserName,
		Password: string(password),
	}, nil
}

func GetElasticsearchCA(k8sclient k8s.Client, es esv1.Elasticsearch) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	secretName := certificates.PublicCertsSecretName(esv1.ESNamer, es.Name)
	var secret corev1.Secret
	nsn := types.NamespacedName{
		Name:      secretName,
		Namespace: es.Namespace,
	}
	log.V(1).Info("Retrieving CA secret for Elasticsearch", "secret_name", secretName)
	err := k8sclient.Get(nsn, &secret)
	if err != nil {
		return certs, errors.WithStack(err)
	}
	certBytes := secret.Data[certificates.CAFileName]
	if len(certBytes) == 0 {
		return certs, fmt.Errorf("ca secret %s is missing key %s", secretName, certificates.CAFileName)
	}

	certs, err = certificates.ParsePEMCerts(certBytes)
	if err != nil {
		log.Error(err, "error parsing CA secret", "secret_name", secretName, "elasticsearch_name", es.Name)
	}
	return certs, err
}