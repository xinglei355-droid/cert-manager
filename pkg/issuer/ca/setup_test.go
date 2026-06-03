/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func mustGenerateCACertAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := pki.GenerateRSAPrivateKey(2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		DNSNames:              []string{"ca.example.com"},
	}

	certDER, err := x509.CreateCertificate(nil, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM, err := pki.EncodeX509(cert)
	require.NoError(t, err)

	keyPEM := pki.EncodePKCS1PrivateKey(key)

	return cert, key, certPEM, keyPEM
}

func mustGenerateNonCACertAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := pki.GenerateRSAPrivateKey(2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              []string{"leaf.example.com"},
	}

	caCert, caKey, _, _ := mustGenerateCACertAndKey(t)

	certDER, err := x509.CreateCertificate(nil, template, caCert, key.Public(), caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM, err := pki.EncodeX509(cert)
	require.NoError(t, err)

	keyPEM := pki.EncodePKCS1PrivateKey(key)

	return cert, key, certPEM, keyPEM
}

func TestCA_Setup(t *testing.T) {
	const (
		testNamespace   = "test-namespace"
		testSecretName  = "test-ca-secret"
		clusterResourceNS = "cluster-resource-namespace"
	)

	_, _, caCertPEM, caKeyPEM := mustGenerateCACertAndKey(t)
	_, _, nonCACertPEM, nonCAKeyPEM := mustGenerateNonCACertAndKey(t)

	tests := []struct {
		name              string
		issuer            *v1.Issuer
		secret            *corev1.Secret
		secretErr         error
		expectCond        string
		expectCondPrefix  string
		expectErr         string
	}{
		{
			name: "valid CA issuer with CA certificate",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSCertKey:       caCertPEM,
					corev1.TLSPrivateKeyKey: caKeyPEM,
				},
			},
			expectCond: "Ready True: KeyPairVerified: Signing CA verified",
		},
		{
			name: "secret does not exist",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secretErr: apierrors.NewNotFound(corev1.Resource("secrets"), testSecretName),
			expectCondPrefix: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: secrets",
			expectErr:        "secrets",
		},
		{
			name: "secret exists but TLS cert data is missing",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSPrivateKeyKey: caKeyPEM,
				},
			},
			expectCond: fmt.Sprintf(`Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: no data for %q in secret '%s/%s'`, corev1.TLSCertKey, testNamespace, testSecretName),
			expectErr:  fmt.Sprintf(`Error getting keypair for CA issuer: no data for %q in secret '%s/%s'`, corev1.TLSCertKey, testNamespace, testSecretName),
		},
		{
			name: "secret exists but TLS cert data is invalid",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("not-a-valid-cert"),
					corev1.TLSPrivateKeyKey: caKeyPEM,
				},
			},
			expectCondPrefix: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: error decoding certificate PEM block",
		},
		{
			name: "secret exists but TLS private key data is missing",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSCertKey: caCertPEM,
				},
			},
			expectCond: fmt.Sprintf(`Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: no data for %q in secret '%s/%s'`, corev1.TLSPrivateKeyKey, testNamespace, testSecretName),
			expectErr:  fmt.Sprintf(`Error getting keypair for CA issuer: no data for %q in secret '%s/%s'`, corev1.TLSPrivateKeyKey, testNamespace, testSecretName),
		},
		{
			name: "secret exists but TLS private key data is invalid",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSCertKey:       caCertPEM,
					corev1.TLSPrivateKeyKey: []byte("not-a-valid-key"),
				},
			},
			expectCondPrefix: "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: error decoding private key PEM block",
		},
		{
			name: "certificate is not a CA",
			issuer: &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: testNamespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: testSecretName,
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Data: map[string][]byte{
					corev1.TLSCertKey:       nonCACertPEM,
					corev1.TLSPrivateKeyKey: nonCAKeyPEM,
				},
			},
			expectCond: fmt.Sprintf(`Ready False: ErrInvalidKeyPair: Signing CA certificate is not a CA: certificate signed by secret %q is not a CA`, testSecretName),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := record.NewFakeRecorder(10)

			c := &CA{
				Context: &controller.Context{
					Recorder: recorder,
					IssuerOptions: controller.IssuerOptions{
						ClusterResourceNamespace: clusterResourceNS,
					},
				},
				secretsLister: &testlisters.FakeSecretLister{
					SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
						return &testlisters.FakeSecretNamespaceLister{
							GetFn: func(name string) (*corev1.Secret, error) {
								if tt.secretErr != nil {
									return nil, tt.secretErr
								}
								if tt.secret != nil {
									return tt.secret, nil
								}
								return nil, apierrors.NewNotFound(corev1.Resource("secrets"), name)
							},
						}
					},
				},
			}

			err := c.Setup(t.Context(), tt.issuer)

			if tt.expectErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectCond != "" {
				require.Len(t, tt.issuer.Status.Conditions, 1)
				cond := tt.issuer.Status.Conditions[0]
				gotCond := fmt.Sprintf("%s %s: %s: %s", cond.Type, cond.Status, cond.Reason, cond.Message)
				assert.Equal(t, tt.expectCond, gotCond)
			}
			if tt.expectCondPrefix != "" {
				require.Len(t, tt.issuer.Status.Conditions, 1)
				cond := tt.issuer.Status.Conditions[0]
				gotCond := fmt.Sprintf("%s %s: %s: %s", cond.Type, cond.Status, cond.Reason, cond.Message)
				assert.True(t, strings.HasPrefix(gotCond, tt.expectCondPrefix), "expected condition to start with %q, got %q", tt.expectCondPrefix, gotCond)
			}
		})
	}
}

func TestCA_Setup_ConditionPreservesUnderlyingError(t *testing.T) {
	const (
		testNamespace  = "test-namespace"
		testSecretName = "missing-secret"
	)

	issuer := &v1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: testNamespace,
		},
		Spec: v1.IssuerSpec{
			IssuerConfig: v1.IssuerConfig{
				CA: &v1.CAIssuer{
					SecretName: testSecretName,
				},
			},
		},
	}

	notFoundErr := apierrors.NewNotFound(corev1.Resource("secrets"), testSecretName)

	recorder := record.NewFakeRecorder(10)
	c := &CA{
		Context: &controller.Context{
			Recorder: recorder,
			IssuerOptions: controller.IssuerOptions{
				ClusterResourceNamespace: "cluster-resource-namespace",
			},
		},
		secretsLister: &testlisters.FakeSecretLister{
			SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
				return &testlisters.FakeSecretNamespaceLister{
					GetFn: func(name string) (*corev1.Secret, error) {
						return nil, notFoundErr
					},
				}
			},
		},
	}

	err := c.Setup(t.Context(), issuer)
	require.Error(t, err)

	require.Len(t, issuer.Status.Conditions, 1)
	cond := issuer.Status.Conditions[0]

	assert.Equal(t, v1.IssuerConditionReady, cond.Type)
	assert.Equal(t, cmmeta.ConditionFalse, cond.Status)
	assert.Equal(t, errorGetKeyPair, cond.Reason)
	assert.Contains(t, cond.Message, notFoundErr.Error())
	assert.Contains(t, cond.Message, testSecretName)
}

func TestCA_Setup_NotCACertificateIncludesSecretName(t *testing.T) {
	const (
		testNamespace  = "test-namespace"
		testSecretName = "non-ca-secret"
	)

	_, _, nonCACertPEM, nonCAKeyPEM := mustGenerateNonCACertAndKey(t)

	issuer := &v1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: testNamespace,
		},
		Spec: v1.IssuerSpec{
			IssuerConfig: v1.IssuerConfig{
				CA: &v1.CAIssuer{
					SecretName: testSecretName,
				},
			},
		},
	}

	recorder := record.NewFakeRecorder(10)
	c := &CA{
		Context: &controller.Context{
			Recorder: recorder,
			IssuerOptions: controller.IssuerOptions{
				ClusterResourceNamespace: "cluster-resource-namespace",
			},
		},
		secretsLister: &testlisters.FakeSecretLister{
			SecretsFn: func(namespace string) corelisters.SecretNamespaceLister {
				return &testlisters.FakeSecretNamespaceLister{
					GetFn: func(name string) (*corev1.Secret, error) {
						return &corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
							Data: map[string][]byte{
								corev1.TLSCertKey:       nonCACertPEM,
								corev1.TLSPrivateKeyKey: nonCAKeyPEM,
							},
						}, nil
					},
				}
			},
		},
	}

	err := c.Setup(t.Context(), issuer)
	require.NoError(t, err)

	require.Len(t, issuer.Status.Conditions, 1)
	cond := issuer.Status.Conditions[0]

	assert.Equal(t, v1.IssuerConditionReady, cond.Type)
	assert.Equal(t, cmmeta.ConditionFalse, cond.Status)
	assert.Equal(t, errorInvalidKeyPair, cond.Reason)
	assert.Contains(t, cond.Message, testSecretName)
	assert.Contains(t, cond.Message, "not a CA")
}
