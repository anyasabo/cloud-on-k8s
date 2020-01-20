package monitoring

import (
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewMetricbeatDeployment(es *esv1.Elasticsearch) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      esv1.MetricbeatDeployment(es.Name),
			Namespace: es.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{

			},
		},
	}

}

// func GetMetricbeatDeploymentName(es *esv1.Elasticsearch) string {
// 	return esv1.MetricbeatDeployment(es.Name)
// }

// docker.elastic.co/beats/metricbeat
