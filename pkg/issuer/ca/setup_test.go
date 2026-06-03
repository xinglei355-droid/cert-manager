/*
Copyright 2024 The cert-manager Authors.

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestCA_Setup(t *testing.T) {
	caPk, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		t.Fatal(err)
	}
	caCert := mustCreateCACertificate(t, caPk, "test-ca")

	nonCAPk, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		t.Fatal(err)
	}
	nonCACert := mustCreateNonCACertificate(t, nonCAPk, caCert, caPk)

	secretName := "ca-secret"
	namespace := "test-namespace"

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       caCert.Raw,
			corev1.TLSPrivateKeyKey: x509.MarshalPKCS1PrivateKey(caPk),
		},
	}

	nonCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       nonCACert.Raw,
			corev1.TLSPrivateKeyKey: x509.MarshalPKCS1PrivateKey(nonCAPk),
		},
	}

	notFoundErr := apierrors.NewNotFound(corev1.Resource("secret"), secretName)

	tests := map[string]struct {
		secret         *corev1.Secret
		secretGetErr   error
		expectCond     string
		expectEvent    string
		expectErr      bool
		expectErrMatch string
	}{
		"secret not found should return error with underlying error in condition": {
			secretGetErr:   notFoundErr,
			expectCond:     "Ready False: ErrGetKeyPair: Error getting keypair for CA issuer: " + notFoundErr.Error(),
			expectEvent:    "Warning ErrGetKeyPair Error getting keypair for CA issuer: " + notFoundErr.Error(),
			expectErr:      true,
			expectErrMatch: notFoundErr.Error(),
		},
		"secret exists but certificate is not a CA should include secret name in condition": {
			secret: nonCASecret,
			expectCond: "Ready False: ErrInvalidKeyPair: Error getting keypair for CA issuer: " +
				"certificate in Secret \"" + namespace + "/" + secretName + "\" is not a CA",
			expectEvent: "Warning ErrInvalidKeyPair Error getting keypair for CA issuer: " +
				"certificate in Secret \"" + namespace + "/" + secretName + "\" is not a CA",
		},
		"valid CA secret should be ready": {
			secret:      caSecret,
			expectCond:  "Ready True: KeyPairVerified: Signing CA verified",
			expectEvent: "Normal KeyPairVerified Signing CA verified",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := &v1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: namespace,
				},
				Spec: v1.IssuerSpec{
					IssuerConfig: v1.IssuerConfig{
						CA: &v1.CAIssuer{
							SecretName: secretName,
						},
					},
				},
			}
			recorder := new(controllertest.FakeRecorder)

			c := &CA{
				Context: &controller.Context{
					Recorder: recorder,
				},
				secretsLister: &testlisters.FakeSecretLister{
					SecretsFn: func(ns string) corelisters.SecretNamespaceLister {
						return &testlisters.FakeSecretNamespaceLister{
							GetFn: func(name string) (ret *corev1.Secret, err error) {
								if test.secretGetErr != nil {
									return nil, test.secretGetErr
								}
								return test.secret, nil
							},
						}
					},
				},
			}

			err := c.Setup(t.Context(), issuer)
			if test.expectErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if test.expectErrMatch != "" && !containsString(err.Error(), test.expectErrMatch) {
					t.Errorf("expected error to contain %q, got %q", test.expectErrMatch, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if test.expectCond != "" {
				if len(issuer.Status.Conditions) != 1 {
					t.Fatalf("expected 1 condition, got %d", len(issuer.Status.Conditions))
				}
				gotCond := fmt.Sprintf("%s %s: %s: %s",
					issuer.Status.Conditions[0].Type,
					issuer.Status.Conditions[0].Status,
					issuer.Status.Conditions[0].Reason,
					issuer.Status.Conditions[0].Message)
				if gotCond != test.expectCond {
					t.Errorf("unexpected condition:\n  got: %q\n want: %q", gotCond, test.expectCond)
				}
			}

			if test.expectEvent != "" {
				if len(recorder.Events) != 1 {
					t.Fatalf("expected 1 event, got %d: %v", len(recorder.Events), recorder.Events)
				}
				if recorder.Events[0] != test.expectEvent {
					t.Errorf("unexpected event:\n  got: %q\n want: %q", recorder.Events[0], test.expectEvent)
				}
			}
		})
	}
}

func mustCreateCACertificate(t *testing.T, pk *rsa.PrivateKey, commonName string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustCreateNonCACertificate(t *testing.T, pk *rsa.PrivateKey, caCert *x509.Certificate, caPk *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-non-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pk.Public(), caPk)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}