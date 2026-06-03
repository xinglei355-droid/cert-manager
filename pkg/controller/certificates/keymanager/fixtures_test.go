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
	"crypto"
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
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const (
	testNamespace  = "testns"
	testCertName   = "test-cert"
	testSecretName = "test-secret"
)

func new(s string) *string {
	return &s
}

func mustGeneratePKCS8RSA(t *testing.T, keySize int) []byte {
	t.Helper()
	pk, err := pki.GenerateRSAPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustGeneratePKCS8ECDSA(t *testing.T, keySize int) []byte {
	t.Helper()
	pk, err := pki.GenerateECPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustGeneratePKCS8Ed25519(t *testing.T) []byte {
	t.Helper()
	pk, err := pki.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := pki.EncodePKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func decodePrivateKey(t *testing.T, data []byte) crypto.Signer {
	t.Helper()
	pk, err := pki.DecodePrivateKeyBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func newSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      name,
		},
		Data: data,
	}
}

func newOwnedNextPrivateKeySecret(name, owner string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      name,
			Labels: map[string]string{
				cmapi.IsNextPrivateKeySecretLabelKey:      "true",
				cmapi.PartOfCertManagerControllerLabelKey: "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: owner, UID: types.UID(owner)},
				}, certificateGvk),
			},
		},
		Data: data,
	}
}

type KeyManagerFixture struct {
	Certificate *cmapi.Certificate
	Secrets     []runtime.Object
}

func (f *KeyManagerFixture) WithCertificate(crt *cmapi.Certificate) *KeyManagerFixture {
	f.Certificate = crt
	return f
}

func (f *KeyManagerFixture) WithSecrets(secrets ...runtime.Object) *KeyManagerFixture {
	f.Secrets = secrets
	return f
}

type KeyManagerExpectedActions struct {
	Actions []testpkg.Action
	Events  []string
}

func (e *KeyManagerExpectedActions) WithActions(actions ...testpkg.Action) *KeyManagerExpectedActions {
	e.Actions = actions
	return e
}

func (e *KeyManagerExpectedActions) WithEvents(events ...string) *KeyManagerExpectedActions {
	e.Events = events
	return e
}

type PrivateKeyRotationTestCase struct {
	Name            string
	Fixture         *KeyManagerFixture
	ExpectedActions *KeyManagerExpectedActions
	Verify          func(t *testing.T, b *testpkg.Builder)
}

func newIssuingCertificate(name string, mods ...gen.CertificateModifier) *cmapi.Certificate {
	baseMods := []gen.CertificateModifier{
		gen.SetCertificateNamespace(testNamespace),
		gen.SetCertificateSecretName(testSecretName),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}),
	}
	return gen.Certificate(name, append(baseMods, mods...)...)
}

func newIssuingCertificateWithUID(name string, mods ...gen.CertificateModifier) *cmapi.Certificate {
	baseMods := []gen.CertificateModifier{
		gen.SetCertificateNamespace(testNamespace),
		gen.SetCertificateUID(types.UID(name)),
		gen.SetCertificateSecretName(testSecretName),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}),
	}
	return gen.Certificate(name, append(baseMods, mods...)...)
}

func expectedCreateActionForSecret(name string, data map[string][]byte) testpkg.Action {
	return testpkg.NewCustomMatch(coretesting.NewCreateAction(
		corev1.SchemeGroupVersion.WithResource("secrets"),
		testNamespace,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       testNamespace,
				Name:            name,
				Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testCertName}}, certificateGvk)},
			},
			Data: data,
		},
	), relaxedSecretMatcher)
}

func expectedCreateActionForSecretWithGenerateName(data map[string][]byte) testpkg.Action {
	return testpkg.NewCustomMatch(coretesting.NewCreateAction(
		corev1.SchemeGroupVersion.WithResource("secrets"),
		testNamespace,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       testNamespace,
				GenerateName:    testCertName + "-",
				Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testCertName}}, certificateGvk)},
			},
			Data: data,
		},
	), relaxedSecretMatcher)
}

func expectedUpdateStatusAction(nextPrivateKeySecretName *string, mods ...gen.CertificateModifier) testpkg.Action {
	baseMods := []gen.CertificateModifier{
		gen.SetCertificateNamespace(testNamespace),
		gen.SetCertificateSecretName(testSecretName),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}),
	}
	crt := gen.Certificate(testCertName, append(baseMods, mods...)...)
	if nextPrivateKeySecretName != nil {
		crt.Status.NextPrivateKeySecretName = nextPrivateKeySecretName
	}
	return testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
		cmapi.SchemeGroupVersion.WithResource("certificates"),
		"status",
		testNamespace,
		crt,
	))
}

func expectedGetCertificateAction() testpkg.Action {
	return testpkg.NewAction(coretesting.NewGetAction(
		cmapi.SchemeGroupVersion.WithResource("certificates"),
		testNamespace,
		testCertName,
	))
}

func FixtureSecretMissingRotationPolicyNever(t *testing.T) *PrivateKeyRotationTestCase {
	t.Helper()
	return &PrivateKeyRotationTestCase{
		Name: "secret_missing_rotation_policy_never",
		Fixture: (&KeyManagerFixture{}).
			WithCertificate(newIssuingCertificate(testCertName,
				gen.SetCertificateRotationPolicy(cmapi.RotationPolicyNever),
			)),
		ExpectedActions: (&KeyManagerExpectedActions{}).
			WithActions(
				expectedUpdateStatusAction(new("test-cert-notrandom"),
					gen.SetCertificateRotationPolicy(cmapi.RotationPolicyNever),
				),
				expectedCreateActionForSecretWithGenerateName(map[string][]byte{"tls.key": nil}),
			).
			WithEvents("Normal Generated Stored new private key in temporary Secret resource \"test-cert-notrandom\""),
		Verify: func(t *testing.T, b *testpkg.Builder) {
			t.Helper()
			crt, err := b.FakeCMClient().CertmanagerV1().Certificates(testNamespace).Get(t.Context(), testCertName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error getting certificate: %v", err)
			}
			if crt.Status.NextPrivateKeySecretName == nil {
				t.Fatal("expected NextPrivateKeySecretName to be set, got nil")
			}
			t.Logf("NextPrivateKeySecretName: %s", *crt.Status.NextPrivateKeySecretName)

			secrets, err := b.FakeKubeClient().CoreV1().Secrets(testNamespace).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("unexpected error listing secrets: %v", err)
			}
			if len(secrets.Items) != 1 {
				t.Fatalf("expected 1 secret, got %d", len(secrets.Items))
			}
			secret := secrets.Items[0]
			if secret.Data == nil || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
				t.Fatal("expected secret to contain tls.key data")
			}
			pk := decodePrivateKey(t, secret.Data[corev1.TLSPrivateKeyKey])
			violations := pki.PrivateKeyMatchesSpec(pk, cmapi.CertificateSpec{
				PrivateKey: &cmapi.CertificatePrivateKey{},
			})
			if len(violations) > 0 {
				t.Fatalf("expected private key to match spec, got violations: %v", violations)
			}
		},
	}
}

func FixtureSecretAlgorithmMismatchRotationPolicyNever(t *testing.T) *PrivateKeyRotationTestCase {
	t.Helper()
	ecdsaKey := mustGeneratePKCS8ECDSA(t, pki.ECCurve256)
	return &PrivateKeyRotationTestCase{
		Name: "secret_algorithm_mismatch_rotation_policy_never",
		Fixture: (&KeyManagerFixture{}).
			WithCertificate(newIssuingCertificate(testCertName,
				gen.SetCertificateRotationPolicy(cmapi.RotationPolicyNever),
				gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			)).
			WithSecrets(newSecret(testSecretName, map[string][]byte{
				corev1.TLSPrivateKeyKey: ecdsaKey,
			})),
		ExpectedActions: (&KeyManagerExpectedActions{}).
			WithEvents("Warning CannotRegenerateKey User intervention required: existing private key in Secret \"test-secret\" does not match requirements on Certificate resource, mismatching fields: [spec.privateKey.algorithm], but cert-manager cannot create new private key as the Certificate's .spec.privateKey.rotationPolicy is unset or set to Never. To allow cert-manager to create a new private key you can set .spec.privateKey.rotationPolicy to 'Always' (this will result in the private key being regenerated every time a cert is renewed) "),
		Verify: func(t *testing.T, b *testpkg.Builder) {
			t.Helper()
			crt, err := b.FakeCMClient().CertmanagerV1().Certificates(testNamespace).Get(t.Context(), testCertName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error getting certificate: %v", err)
			}
			if crt.Status.NextPrivateKeySecretName != nil {
				t.Fatalf("expected NextPrivateKeySecretName to be nil, got %s", *crt.Status.NextPrivateKeySecretName)
			}

			secrets, err := b.FakeKubeClient().CoreV1().Secrets(testNamespace).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("unexpected error listing secrets: %v", err)
			}
			nextPKSecrets := 0
			for _, s := range secrets.Items {
				if s.Labels[cmapi.IsNextPrivateKeySecretLabelKey] == "true" {
					nextPKSecrets++
				}
			}
			if nextPKSecrets > 0 {
				t.Fatalf("expected no next private key secrets to be created, got %d", nextPKSecrets)
			}
		},
	}
}

func FixtureSecretMatchesRotationPolicyNever(t *testing.T) *PrivateKeyRotationTestCase {
	t.Helper()
	rsaKey := mustGeneratePKCS8RSA(t, 2048)
	return &PrivateKeyRotationTestCase{
		Name: "secret_matches_rotation_policy_never",
		Fixture: (&KeyManagerFixture{}).
			WithCertificate(newIssuingCertificateWithUID(testCertName,
				gen.SetCertificateRotationPolicy(cmapi.RotationPolicyNever),
				gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			)).
			WithSecrets(newSecret(testSecretName, map[string][]byte{
				corev1.TLSPrivateKeyKey: rsaKey,
			})),
		ExpectedActions: (&KeyManagerExpectedActions{}).
			WithActions(
				expectedUpdateStatusAction(new("test-cert-notrandom"),
					gen.SetCertificateRotationPolicy(cmapi.RotationPolicyNever),
					gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
					gen.SetCertificateKeySize(2048),
				),
				expectedCreateActionForSecretWithGenerateName(map[string][]byte{"tls.key": nil}),
			).
			WithEvents("Normal Reused Reusing private key stored in existing Secret resource \"test-secret\""),
		Verify: func(t *testing.T, b *testpkg.Builder) {
			t.Helper()
			crt, err := b.FakeCMClient().CertmanagerV1().Certificates(testNamespace).Get(t.Context(), testCertName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error getting certificate: %v", err)
			}
			if crt.Status.NextPrivateKeySecretName == nil {
				t.Fatal("expected NextPrivateKeySecretName to be set, got nil")
			}

			secrets, err := b.FakeKubeClient().CoreV1().Secrets(testNamespace).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("unexpected error listing secrets: %v", err)
			}
			nextPKSecrets := 0
			var nextPKSecret corev1.Secret
			for _, s := range secrets.Items {
				if s.Labels[cmapi.IsNextPrivateKeySecretLabelKey] == "true" {
					nextPKSecrets++
					nextPKSecret = s
				}
			}
			if nextPKSecrets != 1 {
				t.Fatalf("expected 1 next private key secret, got %d", nextPKSecrets)
			}
			if nextPKSecret.Data == nil || len(nextPKSecret.Data[corev1.TLSPrivateKeyKey]) == 0 {
				t.Fatal("expected next private key secret to contain tls.key data")
			}
			pk := decodePrivateKey(t, nextPKSecret.Data[corev1.TLSPrivateKeyKey])
			violations := pki.PrivateKeyMatchesSpec(pk, cmapi.CertificateSpec{
				PrivateKey: &cmapi.CertificatePrivateKey{
					Algorithm: cmapi.RSAKeyAlgorithm,
					Size:      2048,
				},
			})
			if len(violations) > 0 {
				t.Fatalf("expected re-used private key to match spec, got violations: %v", violations)
			}
		},
	}
}

func FixtureRotationPolicyAlways(t *testing.T) *PrivateKeyRotationTestCase {
	t.Helper()
	return &PrivateKeyRotationTestCase{
		Name: "rotation_policy_always",
		Fixture: (&KeyManagerFixture{}).
			WithCertificate(newIssuingCertificate(testCertName,
				gen.SetCertificateRotationPolicy(cmapi.RotationPolicyAlways),
				gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			)),
		ExpectedActions: (&KeyManagerExpectedActions{}).
			WithActions(
				expectedUpdateStatusAction(new("test-cert-notrandom"),
					gen.SetCertificateRotationPolicy(cmapi.RotationPolicyAlways),
					gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
					gen.SetCertificateKeySize(2048),
				),
				expectedCreateActionForSecretWithGenerateName(map[string][]byte{"tls.key": nil}),
			).
			WithEvents("Normal Generated Stored new private key in temporary Secret resource \"test-cert-notrandom\""),
		Verify: func(t *testing.T, b *testpkg.Builder) {
			t.Helper()
			crt, err := b.FakeCMClient().CertmanagerV1().Certificates(testNamespace).Get(t.Context(), testCertName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error getting certificate: %v", err)
			}
			if crt.Status.NextPrivateKeySecretName == nil {
				t.Fatal("expected NextPrivateKeySecretName to be set, got nil")
			}

			secrets, err := b.FakeKubeClient().CoreV1().Secrets(testNamespace).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("unexpected error listing secrets: %v", err)
			}
			if len(secrets.Items) != 1 {
				t.Fatalf("expected 1 secret, got %d", len(secrets.Items))
			}
			secret := secrets.Items[0]
			if secret.Data == nil || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
				t.Fatal("expected secret to contain tls.key data")
			}
			pk := decodePrivateKey(t, secret.Data[corev1.TLSPrivateKeyKey])
			violations := pki.PrivateKeyMatchesSpec(pk, cmapi.CertificateSpec{
				PrivateKey: &cmapi.CertificatePrivateKey{
					Algorithm: cmapi.RSAKeyAlgorithm,
					Size:      2048,
				},
			})
			if len(violations) > 0 {
				t.Fatalf("expected private key to match spec, got violations: %v", violations)
			}
		},
	}
}

func FixtureRotationPolicyAlwaysWithExistingSecret(t *testing.T) *PrivateKeyRotationTestCase {
	t.Helper()
	existingKey := mustGeneratePKCS8ECDSA(t, pki.ECCurve256)
	return &PrivateKeyRotationTestCase{
		Name: "rotation_policy_always_with_existing_secret",
		Fixture: (&KeyManagerFixture{}).
			WithCertificate(newIssuingCertificate(testCertName,
				gen.SetCertificateRotationPolicy(cmapi.RotationPolicyAlways),
				gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			)).
			WithSecrets(newSecret(testSecretName, map[string][]byte{
				corev1.TLSPrivateKeyKey: existingKey,
			})),
		ExpectedActions: (&KeyManagerExpectedActions{}).
			WithActions(
				expectedUpdateStatusAction(new("test-cert-notrandom"),
					gen.SetCertificateRotationPolicy(cmapi.RotationPolicyAlways),
					gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
					gen.SetCertificateKeySize(2048),
				),
				expectedCreateActionForSecretWithGenerateName(map[string][]byte{"tls.key": nil}),
			).
			WithEvents("Normal Generated Stored new private key in temporary Secret resource \"test-cert-notrandom\""),
		Verify: func(t *testing.T, b *testpkg.Builder) {
			t.Helper()
			crt, err := b.FakeCMClient().CertmanagerV1().Certificates(testNamespace).Get(t.Context(), testCertName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("unexpected error getting certificate: %v", err)
			}
			if crt.Status.NextPrivateKeySecretName == nil {
				t.Fatal("expected NextPrivateKeySecretName to be set, got nil")
			}

			secrets, err := b.FakeKubeClient().CoreV1().Secrets(testNamespace).List(t.Context(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("unexpected error listing secrets: %v", err)
			}
			nextPKSecrets := 0
			var nextPKSecret corev1.Secret
			for _, s := range secrets.Items {
				if s.Labels[cmapi.IsNextPrivateKeySecretLabelKey] == "true" {
					nextPKSecrets++
					nextPKSecret = s
				}
			}
			if nextPKSecrets != 1 {
				t.Fatalf("expected 1 next private key secret, got %d", nextPKSecrets)
			}
			if nextPKSecret.Data == nil || len(nextPKSecret.Data[corev1.TLSPrivateKeyKey]) == 0 {
				t.Fatal("expected next private key secret to contain tls.key data")
			}
			pk := decodePrivateKey(t, nextPKSecret.Data[corev1.TLSPrivateKeyKey])
			violations := pki.PrivateKeyMatchesSpec(pk, cmapi.CertificateSpec{
				PrivateKey: &cmapi.CertificatePrivateKey{
					Algorithm: cmapi.RSAKeyAlgorithm,
					Size:      2048,
				},
			})
			if len(violations) > 0 {
				t.Fatalf("expected new private key to match spec, got violations: %v", violations)
			}
		},
	}
}

func AllPrivateKeyRotationFixtures(t *testing.T) []*PrivateKeyRotationTestCase {
	t.Helper()
	return []*PrivateKeyRotationTestCase{
		FixtureSecretMissingRotationPolicyNever(t),
		FixtureSecretAlgorithmMismatchRotationPolicyNever(t),
		FixtureSecretMatchesRotationPolicyNever(t),
		FixtureRotationPolicyAlways(t),
		FixtureRotationPolicyAlwaysWithExistingSecret(t),
	}
}

func RunPrivateKeyRotationTest(t *testing.T, tc *PrivateKeyRotationTestCase) {
	t.Helper()
	t.Run(tc.Name, func(t *testing.T) {
		builder := &testpkg.Builder{
			T:               t,
			KubeObjects:     tc.Fixture.Secrets,
			CertManagerObjects: []runtime.Object{tc.Fixture.Certificate},
			ExpectedActions: tc.ExpectedActions.Actions,
			ExpectedEvents:  tc.ExpectedActions.Events,
			StringGenerator: func(i int) string { return "notrandom" },
		}
		builder.Init()

		w := &controllerWrapper{}
		_, _, err := w.Register(builder.Context)
		if err != nil {
			t.Fatal(err)
		}

		builder.Start()
		defer builder.Stop()

		err = w.controller.ProcessItem(t.Context(), types.NamespacedName{
			Namespace: testNamespace,
			Name:      testCertName,
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		builder.CheckAndFinish(err)

		if tc.Verify != nil {
			tc.Verify(t, builder)
		}
	})
}