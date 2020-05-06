// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package license

import (
	"testing"

	"github.com/elastic/cloud-on-k8s/pkg/utils/k8s"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestUpdateEnterpriseLicense(t *testing.T) {
	secretName := "my-secret"
	ns := "my-ns"
	nsn := types.NamespacedName{
		Name:      secretName,
		Namespace: ns,
	}
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels: map[string]string{
				"my-label": "value",
			},
		},
	}

	type args struct {
		c      k8s.Client
		secret v1.Secret
		l      EnterpriseLicense
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		assertion func(k8s.Client)
	}{
		{
			name: "updates labels preserving existing ones",
			args: args{
				c:      k8s.WrappedFakeClient(&secret),
				secret: secret,
				l:      licenseFixtureV3,
			},
			wantErr: false,
			assertion: func(client k8s.Client) {
				var sec v1.Secret
				err := client.Get(nsn, &sec)
				require.NoError(t, err)
				require.Equal(t, sec.Labels["my-label"], "value", "obj", sec)
				require.Contains(t, sec.Labels, LicenseLabelScope)
			},
		},
		{
			name: "basic update",
			args: args{
				c:      k8s.WrappedFakeClient(&secret),
				secret: secret,
				l:      licenseFixtureV3,
			},
			wantErr: false,
			assertion: func(client k8s.Client) {
				var sec v1.Secret
				err := client.Get(nsn, &sec)
				require.NoError(t, err)
				require.Equal(t, string(licenseFixtureV3.License.Type), sec.Labels[LicenseLabelType])
				require.Equal(t, string(LicenseScopeOperator), sec.Labels[LicenseLabelScope])
				require.Len(t, sec.Data, 1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := UpdateEnterpriseLicense(tt.args.c, tt.args.secret, tt.args.l); (err != nil) != tt.wantErr {
				t.Errorf("UpdateEnterpriseLicense() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.assertion != nil {
				tt.assertion(tt.args.c)
			}
		})
	}
}
