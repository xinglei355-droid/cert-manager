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

package keymanager

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

type fixtureBuilder struct {
	t *testing.T

	namespace string
	certName  string
	secretName string

	rotationPolicy cmapi.PrivateKeyRotationPolicy
	algorithm      cmapi.PrivateKeyAlgorithm
	keySize        int

	secretExists       bool
	secretData         map[string][]byte
	secretOwned        bool
	secretNameOverride string

	issuingCondition cmmeta.ConditionStatus
}

func newFixtureBuilder(t *testing.T) *fixtureBuilder {
	return &fixtureBuilder{
		t:                t,
		namespace:        "testns",
		certName:         "testcert",
		secretName:       "testsecret",
		rotationPolicy:   cmapi.RotationPolicyAlways,
		algorithm:        cmapi.RSAKeyAlgorithm,
		keySize:          2048,
		issuingCondition: cmmeta.ConditionTrue,
	}
}

func (b *fixtureBuilder) withNamespace(ns string) *fixtureBuilder {
	b.namespace = ns
	return b
}

func (b *fixtureBuilder) withCertName(name string) *fixtureBuilder {
	b.certName = name
	return b
}

func (b *fixtureBuilder) withSecretName(name string) *fixtureBuilder {
	b.secretName = name
	return b
}

func (b *fixtureBuilder) withRotationPolicy(policy cmapi.PrivateKeyRotationPolicy) *fixtureBuilder {
	b.rotationPolicy = policy
	return b
}

func (b *fixtureBuilder) withAlgorithm(algo cmapi.PrivateKeyAlgorithm) *fixtureBuilder {
	b.algorithm = algo
	return b
}

func (b *fixtureBuilder) withKeySize(size int) *fixtureBuilder {
	b.keySize = size
	return b
}

func (b *fixtureBuilder) withSecretExists(exists bool) *fixtureBuilder {
	b.secretExists = exists
	return b
}

func (b *fixtureBuilder) withSecretData(data map[string][]byte) *fixtureBuilder {
	b.secretData = data
	return b
}

func (b *fixtureBuilder) withSecretOwned(owned bool) *fixtureBuilder {
	b.secretOwned = owned
	return b
}

func (b *fixtureBuilder) withSecretNameOverride(name string) *fixtureBuilder {
	b.secretNameOverride = name
	return b
}

func (b *fixtureBuilder) withIssuingCondition(status cmmeta.ConditionStatus) *fixtureBuilder {
	b.issuingCondition = status
	return b
}

func (b *fixtureBuilder) build() (*cmapi.Certificate, []runtime.Object) {
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.namespace,
			Name:      b.certName,
			UID:       types.UID(b.certName),
		},
		Spec: cmapi.CertificateSpec{
			SecretName: b.secretName,
			DNSNames:   []string{"example.com"},
			IssuerRef: cmmeta.IssuerReference{
				Name: "testissuer",
			},
			PrivateKey: &cmapi.CertificatePrivateKey{
				RotationPolicy: b.rotationPolicy,
				Algorithm:      b.algorithm,
				Size:           b.keySize,
			},
		},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{
				{
					Type:   cmapi.CertificateConditionIssuing,
					Status: b.issuingCondition,
				},
			},
		},
	}

	var objects []runtime.Object
	if b.secretExists {
		secret := b.buildSecret()
		objects = append(objects, secret)
	}

	return crt, objects
}

func (b *fixtureBuilder) buildSecret() *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.namespace,
			Name:      b.secretName,
		},
		Data: b.secretData,
	}

	if b.secretOwned {
		secret.Labels = map[string]string{
			cmapi.IsNextPrivateKeySecretLabelKey:      "true",
			cmapi.PartOfCertManagerControllerLabelKey: "true",
		}
		secret.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(&cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: b.namespace,
					Name:      b.certName,
					UID:       types.UID(b.certName),
				},
			}, certificateGvk),
		}
	}

	return secret
}

func (b *fixtureBuilder) runTest(expectedActions []testpkg.Action, expectedEvents []string, expectedErr string) {
	crt, secrets := b.build()

	builder := &testpkg.Builder{
		T:               b.t,
		ExpectedEvents:  expectedEvents,
		ExpectedActions: expectedActions,
		StringGenerator: func(i int) string { return "notrandom" },
	}
	if crt != nil {
		builder.CertManagerObjects = append(builder.CertManagerObjects, crt)
	}
	if secrets != nil {
		builder.KubeObjects = append(builder.KubeObjects, secrets...)
	}
	builder.Init()

	w := &controllerWrapper{}
	_, _, err := w.Register(builder.Context)
	if err != nil {
		b.t.Fatal(err)
	}
	builder.Start()
	defer builder.Stop()

	key := types.NamespacedName{
		Name:      crt.Name,
		Namespace: crt.Namespace,
	}

	err = w.controller.ProcessItem(b.t.Context(), key)
	switch {
	case err != nil:
		if expectedErr != err.Error() {
			b.t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), expectedErr)
		}
	default:
		if expectedErr != "" {
			b.t.Errorf("got no error but expected: %s", expectedErr)
		}
	}

	if err := builder.AllEventsCalled(); err != nil {
		builder.T.Error(err)
	}
	if err := builder.AllActionsExecuted(); err != nil {
		builder.T.Error(err)
	}
}

func TestPrivateKeyRotation_SecretMissing(t *testing.T) {
	t.Run("rotationPolicy=Always with no existing Secret should create new key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(false)

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testcert-notrandom"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
			testpkg.NewCustomMatch(coretesting.NewCreateAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "testns",
						GenerateName:    "testcert-",
						Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"}}, certificateGvk)},
					},
					Data: map[string][]byte{"tls.key": nil},
				},
			), relaxedSecretMatcher),
		}

		expectedEvents := []string{`Normal Generated Stored new private key in temporary Secret resource "testcert-notrandom"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})

	t.Run("rotationPolicy=Never with no existing Secret should create new key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyNever).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(false)

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testcert-notrandom"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
			testpkg.NewCustomMatch(coretesting.NewCreateAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "testns",
						GenerateName:    "testcert-",
						Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"}}, certificateGvk)},
					},
					Data: map[string][]byte{"tls.key": nil},
				},
			), relaxedSecretMatcher),
		}

		expectedEvents := []string{`Normal Generated Stored new private key in temporary Secret resource "testcert-notrandom"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})
}

func TestPrivateKeyRotation_AlgorithmMismatch(t *testing.T) {
	t.Run("rotationPolicy=Always with RSA Secret but ECDSA spec should delete and regenerate", func(t *testing.T) {
		rsaKeyBytes := mustGenerateRSA(t, 2048)

		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.ECDSAKeyAlgorithm).
			withKeySize(256).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: rsaKeyBytes}).
			withSecretOwned(true).
			withSecretNameOverride("existing-secret")

		crt, _ := fixture.build()

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewDeleteAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				"existing-secret",
			)),
		}

		expectedEvents := []string{"Normal Deleted Regenerating private key due to change in fields: [spec.privateKey.algorithm]"}

		crt.Status.NextPrivateKeySecretName = newString("existing-secret")
		fixture.runTestWithCertificate(crt, expectedActions, expectedEvents, "")
	})

	t.Run("rotationPolicy=Never with RSA Secret but ECDSA spec should warn and not regenerate", func(t *testing.T) {
		rsaKeyBytes := mustGenerateRSA(t, 2048)

		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyNever).
			withAlgorithm(cmapi.ECDSAKeyAlgorithm).
			withKeySize(256).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: rsaKeyBytes}).
			withSecretOwned(false)

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewGetAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				"testsecret",
			)),
		}

		expectedEvents := []string{"Warning CannotRegenerateKey User intervention required: existing private key in Secret \"testsecret\" does not match requirements on Certificate resource, mismatching fields: [spec.privateKey.algorithm], but cert-manager cannot create new private key as the Certificate's .spec.privateKey.rotationPolicy is unset or set to Never. To allow cert-manager to create a new private key you can set .spec.privateKey.rotationPolicy to 'Always' (this will result in the private key being regenerated every time a cert is renewed) "}

		fixture.runTest(expectedActions, expectedEvents, "")
	})
}

func TestPrivateKeyRotation_RotationPolicyNever(t *testing.T) {
	t.Run("rotationPolicy=Never with matching Secret should reuse existing key", func(t *testing.T) {
		rsaKeyBytes := mustGenerateRSA(t, 2048)

		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyNever).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: rsaKeyBytes}).
			withSecretOwned(false)

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewGetAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				"testsecret",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testsecret"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
		}

		expectedEvents := []string{`Normal Reused Reusing private key stored in existing Secret resource "testsecret"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})

	t.Run("rotationPolicy=Never with empty Secret data should create new key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyNever).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(true).
			withSecretData(map[string][]byte{})

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewGetAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				"testsecret",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testcert-notrandom"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
			testpkg.NewCustomMatch(coretesting.NewCreateAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "testns",
						GenerateName:    "testcert-",
						Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"}}, certificateGvk)},
					},
					Data: map[string][]byte{"tls.key": nil},
				},
			), relaxedSecretMatcher),
		}

		expectedEvents := []string{`Normal Generated Stored new private key in temporary Secret resource "testcert-notrandom"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})

	t.Run("rotationPolicy=Never with invalid key data should create new key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyNever).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: []byte("invalid-key-data")})

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewGetAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				"testsecret",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testcert-notrandom"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
			testpkg.NewCustomMatch(coretesting.NewCreateAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "testns",
						GenerateName:    "testcert-",
						Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"}}, certificateGvk)},
					},
					Data: map[string][]byte{"tls.key": nil},
				},
			), relaxedSecretMatcher),
		}

		expectedEvents := []string{`Warning DecodeFailed Failed to decode private key stored in Secret "testsecret" - generating new key`, `Normal Generated Stored new private key in temporary Secret resource "testcert-notrandom"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})
}

func TestPrivateKeyRotation_RotationPolicyAlways(t *testing.T) {
	t.Run("rotationPolicy=Always with matching Secret should still regenerate", func(t *testing.T) {
		rsaKeyBytes := mustGenerateRSA(t, 2048)

		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: rsaKeyBytes}).
			withSecretOwned(true).
			withSecretNameOverride("existing-secret")

		crt, _ := fixture.build()
		crt.Status.NextPrivateKeySecretName = newString("existing-secret")

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
		}

		expectedEvents := []string{}

		fixture.runTestWithCertificate(crt, expectedActions, expectedEvents, "")
	})

	t.Run("rotationPolicy=Always with owned secret containing valid key should do nothing", func(t *testing.T) {
		rsaKeyBytes := mustGenerateRSA(t, 2048)

		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(true).
			withSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: rsaKeyBytes}).
			withSecretOwned(true).
			withSecretNameOverride("existing-secret")

		crt, _ := fixture.build()
		crt.Status.NextPrivateKeySecretName = newString("existing-secret")

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
		}

		fixture.runTestWithCertificate(crt, expectedActions, nil, "")
	})

	t.Run("rotationPolicy=Always with no existing Secret should create new key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.ECDSAKeyAlgorithm).
			withKeySize(256).
			withSecretExists(false)

		expectedActions := []testpkg.Action{
			testpkg.NewAction(coretesting.NewGetAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"testns",
				"testcert",
			)),
			testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
				cmapi.SchemeGroupVersion.WithResource("certificates"),
				"status",
				"testns",
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"},
					Status: cmapi.CertificateStatus{
						NextPrivateKeySecretName: newString("testcert-notrandom"),
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionIssuing,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
			)),
			testpkg.NewCustomMatch(coretesting.NewCreateAction(
				corev1.SchemeGroupVersion.WithResource("secrets"),
				"testns",
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:       "testns",
						GenerateName:    "testcert-",
						Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "testcert"}}, certificateGvk)},
					},
					Data: map[string][]byte{"tls.key": nil},
				},
			), relaxedSecretMatcher),
		}

		expectedEvents := []string{`Normal Generated Stored new private key in temporary Secret resource "testcert-notrandom"`}

		fixture.runTest(expectedActions, expectedEvents, "")
	})
}

func TestPrivateKeyRotation_SecretDataVerification(t *testing.T) {
	t.Run("created Secret should contain valid PKCS8 encoded private key", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(false)

		crt, _ := fixture.build()

		builder := &testpkg.Builder{
			T:               t,
			StringGenerator: func(i int) string { return "notrandom" },
		}
		builder.CertManagerObjects = append(builder.CertManagerObjects, crt)
		builder.Init()

		w := &controllerWrapper{}
		_, _, err := w.Register(builder.Context)
		if err != nil {
			t.Fatal(err)
		}
		builder.Start()
		defer builder.Stop()

		key := types.NamespacedName{
			Name:      crt.Name,
			Namespace: crt.Namespace,
		}

		err = w.controller.ProcessItem(t.Context(), key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actions := builder.FakeKubeClient().Actions()
		var createdSecret *corev1.Secret
		for _, action := range actions {
			if action.GetVerb() == "create" && action.GetResource().Resource == "secrets" {
				createdSecret = action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
				break
			}
		}

		if createdSecret == nil {
			t.Fatal("expected Secret to be created but none found")
		}

		pkData, ok := createdSecret.Data[corev1.TLSPrivateKeyKey]
		if !ok {
			t.Fatal("expected tls.key to be present in Secret data")
		}

		pk, err := pki.DecodePrivateKeyBytes(pkData)
		if err != nil {
			t.Fatalf("failed to decode private key from Secret: %v", err)
		}

		violations := pki.PrivateKeyMatchesSpec(pk, *crt)
		if len(violations) > 0 {
			t.Errorf("created private key does not match spec, violations: %v", violations)
		}

		if createdSecret.Labels[cmapi.IsNextPrivateKeySecretLabelKey] != "true" {
			t.Error("expected IsNextPrivateKeySecretLabelKey label to be true")
		}

		if len(createdSecret.OwnerReferences) != 1 {
			t.Error("expected exactly one owner reference")
		}
	})

	t.Run("Certificate status should be updated with NextPrivateKeySecretName", func(t *testing.T) {
		fixture := newFixtureBuilder(t).
			withRotationPolicy(cmapi.RotationPolicyAlways).
			withAlgorithm(cmapi.RSAKeyAlgorithm).
			withKeySize(2048).
			withSecretExists(false)

		crt, _ := fixture.build()

		builder := &testpkg.Builder{
			T:               t,
			StringGenerator: func(i int) string { return "notrandom" },
		}
		builder.CertManagerObjects = append(builder.CertManagerObjects, crt)
		builder.Init()

		w := &controllerWrapper{}
		_, _, err := w.Register(builder.Context)
		if err != nil {
			t.Fatal(err)
		}
		builder.Start()
		defer builder.Stop()

		key := types.NamespacedName{
			Name:      crt.Name,
			Namespace: crt.Namespace,
		}

		err = w.controller.ProcessItem(t.Context(), key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actions := builder.FakeCMClient().Actions()
		var statusUpdated bool
		for _, action := range actions {
			if action.GetVerb() == "update" && action.GetSubresource() == "status" {
				statusUpdated = true
				updatedCrt := action.(coretesting.UpdateAction).GetObject().(*cmapi.Certificate)
				if updatedCrt.Status.NextPrivateKeySecretName == nil {
					t.Error("expected NextPrivateKeySecretName to be set in status")
				} else if *updatedCrt.Status.NextPrivateKeySecretName != "testcert-notrandom" {
					t.Errorf("expected NextPrivateKeySecretName to be 'testcert-notrandom', got %q", *updatedCrt.Status.NextPrivateKeySecretName)
				}
				break
			}
		}

		if !statusUpdated {
			t.Error("expected status update action but none found")
		}
	})
}

func newString(s string) *string {
	return &s
}

func (b *fixtureBuilder) runTestWithCertificate(crt *cmapi.Certificate, expectedActions []testpkg.Action, expectedEvents []string, expectedErr string) {
	var secrets []runtime.Object
	if b.secretExists {
		secret := b.buildSecret()
		secrets = append(secrets, secret)
	}

	builder := &testpkg.Builder{
		T:               b.t,
		ExpectedEvents:  expectedEvents,
		ExpectedActions: expectedActions,
		StringGenerator: func(i int) string { return "notrandom" },
	}
	if crt != nil {
		builder.CertManagerObjects = append(builder.CertManagerObjects, crt)
	}
	if secrets != nil {
		builder.KubeObjects = append(builder.KubeObjects, secrets...)
	}
	builder.Init()

	w := &controllerWrapper{}
	_, _, err := w.Register(builder.Context)
	if err != nil {
		b.t.Fatal(err)
	}
	builder.Start()
	defer builder.Stop()

	key := types.NamespacedName{
		Name:      crt.Name,
		Namespace: crt.Namespace,
	}

	err = w.controller.ProcessItem(b.t.Context(), key)
	switch {
	case err != nil:
		if expectedErr != err.Error() {
			b.t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), expectedErr)
		}
	default:
		if expectedErr != "" {
			b.t.Errorf("got no error but expected: %s", expectedErr)
		}
	}

	if err := builder.AllEventsCalled(); err != nil {
		builder.T.Error(err)
	}
	if err := builder.AllActionsExecuted(); err != nil {
		builder.T.Error(err)
	}
}
