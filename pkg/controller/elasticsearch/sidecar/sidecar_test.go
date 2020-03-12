// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package sidecar

import (
	"testing"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/go-test/deep"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewMonitoringSidecars(t *testing.T) {
	esMon := getEsWithMonitoring()

	tests := []struct {
		name string
		es   esv1.Elasticsearch
		want []corev1.Container
	}{
		{
			name: "monitoring disabled",
			es:   esv1.Elasticsearch{},
			want: []corev1.Container{},
		},
		{
			name: "monitoring enabled",
			es:   esMon,
			want: []corev1.Container{getExpectedContainer(esMon)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewMonitoringSidecars(tc.es)
			if diff := deep.Equal(actual, tc.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

func getEsWithMonitoring() esv1.Elasticsearch {
	return esv1.Elasticsearch{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "es",
			Namespace: "ns",
		},
		Spec: esv1.ElasticsearchSpec{
			Version: "7.6.0",
			Monitoring: esv1.Monitoring{
				ElasticsearchRefs: []esv1.ElasticsearchRef{
					esv1.ElasticsearchRef{
						Name: "monitoring-clus",
					},
				},
			},
		},
	}
}

func getExpectedContainer(es esv1.Elasticsearch) corev1.Container {
	return corev1.Container{
		Name:         MetricbeatContainerNamePrefix,
		Image:        "docker.elastic.co/beats/metricbeat:7.6.0",
		Args:         []string{"-e"},
		Env:          getEnv(es),
		VolumeMounts: newSidecarVolumeMounts(es),
	}
}
