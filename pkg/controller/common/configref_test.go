// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"testing"

	commonv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/driver"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/settings"
	"github.com/elastic/cloud-on-k8s/pkg/controller/common/watches"
	"github.com/elastic/cloud-on-k8s/pkg/utils/k8s"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

type fakeDriver struct {
	client   k8s.Client
	watches  watches.DynamicWatches
	recorder record.EventRecorder
}

func (f fakeDriver) K8sClient() k8s.Client {
	return f.client
}

func (f fakeDriver) DynamicWatches() watches.DynamicWatches {
	return f.watches
}

func (f fakeDriver) Recorder() record.EventRecorder {
	return f.recorder
}

var _ driver.Interface = fakeDriver{}

func TestParseConfigRef(t *testing.T) {
	// any resource Kind would work here (eg. Beat, EnterpriseSearch, etc.)
	resNsn := types.NamespacedName{Namespace: "ns", Name: "resource"}
	res := corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: resNsn.Namespace, Name: resNsn.Name}}
	watchName := ConfigRefWatchName(resNsn)

	tests := []struct {
		name            string
		configRef       *commonv1.ConfigSource
		secretKey       string
		runtimeObjs     []runtime.Object
		want            *settings.CanonicalConfig
		wantErr         bool
		existingWatches []string
		wantWatches     []string
		wantEvent       string
	}{
		{
			name:      "happy path",
			configRef: &commonv1.ConfigSource{SecretRef: commonv1.SecretRef{SecretName: "my-secret"}},
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"configFile.yml": []byte("foo: bar\nbar: baz\n"),
					},
				},
			},
			want:        settings.MustCanonicalConfig(map[string]string{"foo": "bar", "bar": "baz"}),
			wantWatches: []string{watchName},
		},
		{
			name:      "happy path, secret already watched",
			configRef: &commonv1.ConfigSource{SecretRef: commonv1.SecretRef{SecretName: "my-secret"}},
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"configFile.yml": []byte("foo: bar\nbar: baz\n"),
					},
				},
			},
			want:            settings.MustCanonicalConfig(map[string]string{"foo": "bar", "bar": "baz"}),
			existingWatches: []string{watchName},
			wantWatches:     []string{watchName},
		},
		{
			name:      "no configRef specified",
			configRef: nil,
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"configFile.yml": []byte("foo: bar\nbar: baz\n"),
					},
				},
			},
			want:        nil,
			wantWatches: []string{},
		},
		{
			name:      "no configRef specified: clear existing watches",
			configRef: nil,
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"configFile.yml": []byte("foo: bar\nbar: baz\n"),
					},
				},
			},
			want:            nil,
			existingWatches: []string{watchName},
			wantWatches:     []string{},
		},
		{
			name:        "secret not found: error out but watch the future secret",
			configRef:   &commonv1.ConfigSource{SecretRef: commonv1.SecretRef{SecretName: "my-secret"}},
			secretKey:   "configFile.yml",
			runtimeObjs: []runtime.Object{},
			want:        nil,
			wantErr:     true,
			wantWatches: []string{watchName},
		},
		{
			name:      "missing key in the referenced secret: error out, watch the secret and emit an event",
			configRef: &commonv1.ConfigSource{SecretRef: commonv1.SecretRef{SecretName: "my-secret"}},
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"unexpected-key": []byte("foo: bar\nbar: baz\n"),
					},
				},
			},
			wantErr:     true,
			wantWatches: []string{watchName},
			wantEvent:   "Warning Unexpected unable to parse configRef secret ns/my-secret: missing key configFile.yml",
		},
		{
			name:      "invalid config the referenced secret: error out, watch the secret and emit an event",
			configRef: &commonv1.ConfigSource{SecretRef: commonv1.SecretRef{SecretName: "my-secret"}},
			secretKey: "configFile.yml",
			runtimeObjs: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-secret"},
					Data: map[string][]byte{
						"configFile.yml": []byte("that's not yaml"),
					},
				},
			},
			wantErr:     true,
			wantWatches: []string{watchName},
			wantEvent:   "Warning Unexpected unable to parse configFile.yml in configRef secret ns/my-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeRecorder := record.NewFakeRecorder(10)
			w := watches.NewDynamicWatches()
			for _, existingWatch := range tt.existingWatches {
				require.NoError(t, w.Secrets.AddHandler(watches.NamedWatch{Name: existingWatch}))
			}
			d := fakeDriver{
				client:   k8s.WrappedFakeClient(tt.runtimeObjs...),
				watches:  w,
				recorder: fakeRecorder,
			}
			got, err := ParseConfigRef(d, &res, tt.configRef, tt.secretKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseConfigRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantWatches, d.watches.Secrets.Registrations())

			if tt.wantEvent != "" {
				require.Equal(t, tt.wantEvent, <-fakeRecorder.Events)
			} else {
				// no event expected
				select {
				case e := <-fakeRecorder.Events:
					require.Fail(t, "no event expected but got one", "event", e)
				default:
					// ok
				}
			}
		})
	}
}
