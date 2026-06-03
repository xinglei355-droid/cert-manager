package ca

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
)

func TestCA_Setup(t *testing.T) {
	tests := []struct {
		name       string
		secretName string
		secretData map[string][]byte
		expectErr  string
		expectCond string
	}{
		{
			name:       "secret not found",
			secretName: "missing-secret",
			secretData: nil,
			expectErr:  "error getting secret missing-secret: secret \"missing-secret\" not found",
			expectCond: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: error getting secret missing-secret: secret \"missing-secret\" not found",
		},
		{
			name:       "secret missing tls.crt",
			secretName: "bad-secret",
			secretData: map[string][]byte{
				"tls.key": []byte("key"),
			},
			expectErr:  "error decoding cert: error decoding certificate PEM block",
			expectCond: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: error decoding cert: error decoding certificate PEM block",
		},
		{
			name:       "secret missing tls.key",
			secretName: "bad-secret-key",
			secretData: map[string][]byte{
				"tls.crt": []byte("crt"),
			},
			expectErr:  "error decoding cert: error decoding certificate PEM block",
			expectCond: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: error decoding cert: error decoding certificate PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: "test-namespace",
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: tt.secretName,
						},
					},
				},
			}

			c := &CA{
				Context: &controller.Context{
					Recorder: new(controllertest.FakeRecorder),
				},
				secretsLister: &testlisters.FakeSecretLister{
					SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
						return &testlisters.FakeSecretNamespaceLister{
							GetFn: func(name string) (*corev1.Secret, error) {
								if tt.secretData == nil {
									return nil, fmt.Errorf("secret %q not found", name)
								}
								return &corev1.Secret{
									ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
									Data:       tt.secretData,
								}, nil
							},
						}
					},
				},
			}

			err := c.Setup(context.TODO(), issuer)
			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectCond != "" {
				require.Len(t, issuer.Status.Conditions, 1)
				assert.Equal(t, tt.expectCond, fmt.Sprintf("%s %s: %s: %s", issuer.Status.Conditions[0].Type, issuer.Status.Conditions[0].Status, issuer.Status.Conditions[0].Reason, issuer.Status.Conditions[0].Message))
			}
		})
	}
}
