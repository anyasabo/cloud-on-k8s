// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package enterprisesearch

import (
	"testing"

	entv1beta1 "github.com/elastic/cloud-on-k8s/pkg/apis/enterprisesearch/v1beta1"
	"github.com/elastic/cloud-on-k8s/pkg/utils/k8s"
	"github.com/elastic/cloud-on-k8s/test/e2e/test"
	"github.com/stretchr/testify/require"

	// auth on gke
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func (b Builder) CreationTestSteps(k *test.K8sClient) test.StepList {
	return test.StepList{
		{
			Name: "Creating Enterprise Search should succeed",
			Test: func(t *testing.T) {
				for _, obj := range b.RuntimeObjects() {
					err := k.Client.Create(obj)
					require.NoError(t, err)
				}
			},
		},
		{
			Name: "Enterprise Search should be created",
			Test: func(t *testing.T) {
				var createdEnt entv1beta1.EnterpriseSearch
				err := k.Client.Get(k8s.ExtractNamespacedName(&b.EnterpriseSearch), &createdEnt)
				require.NoError(t, err)
				require.Equal(t, b.EnterpriseSearch.Spec.Version, createdEnt.Spec.Version)
			},
		},
	}
}
