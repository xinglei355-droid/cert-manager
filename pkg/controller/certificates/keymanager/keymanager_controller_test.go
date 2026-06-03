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
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func mustGenerateRSA(t *testing.T, keySize int) []byte {
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

func mustGenerateECDSA(t *testing.T, keySize int) []byte {
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

func relaxedSecretMatcher(l coretesting.Action, r coretesting.Action) error {
	objL := l.(coretesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
	objR := r.(coretesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
	for k := range objL.Data {
		objL.Data[k] = []byte("something")
	}
	for k := range objR.Data {
		objR.Data[k] = []byte("something")
	}
	if !reflect.DeepEqual(objL, objR) {
		return fmt.Errorf("unexpected difference between actions (-want +got):\n%s", cmp.Diff(objL, objR))
	}
	return nil
}

type privateKeyRotationFixtureBuilder struct {
	t           *testing.T
	certificate *cmapi.Certificate
	kubeObjects []runtime.Object
}

func newPrivateKeyRotationFixtureBuilder(t *testing.T) *privateKeyRotationFixtureBuilder {
	return &privateKeyRotationFixtureBuilder{
		t: t,
		certificate: &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
			Spec: cmapi.CertificateSpec{
				SecretName: "output",
				PrivateKey: &cmapi.CertificatePrivateKey{
					RotationPolicy: cmapi.RotationPolicyNever,
					Algorithm:      cmapi.RSAKeyAlgorithm,
					Size:           2048,
				},
			},
			Status: cmapi.CertificateStatus{
				Conditions: []cmapi.CertificateCondition{{
					Type:   cmapi.CertificateConditionIssuing,
					Status: cmmeta.ConditionTrue,
				}},
			},
		},
	}
}

func (b *privateKeyRotationFixtureBuilder) WithRotationPolicy(policy cmapi.PrivateKeyRotationPolicy) *privateKeyRotationFixtureBuilder {
	b.certificate.Spec.PrivateKey.RotationPolicy = policy
	return b
}

func (b *privateKeyRotationFixtureBuilder) WithTargetSecretData(data map[string][]byte) *privateKeyRotationFixtureBuilder {
	b.kubeObjects = append(b.kubeObjects, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.certificate.Namespace,
			Name:      b.certificate.Spec.SecretName,
		},
		Data: data,
	})
	return b
}

func (b *privateKeyRotationFixtureBuilder) Build() *privateKeyRotationFixture {
	crt := b.certificate.DeepCopy()

	return &privateKeyRotationFixture{
		t:               b.t,
		certificate:     crt,
		temporarySecret: fmt.Sprintf("%s-notrandom", crt.Name),
		builder: &testpkg.Builder{
			T:                   b.t,
			CertManagerObjects:  []runtime.Object{crt.DeepCopy()},
			KubeObjects:         append([]runtime.Object(nil), b.kubeObjects...),
			StringGenerator:     func(int) string { return "notrandom" },
			ExpectedActions:     nil,
			ExpectedEvents:      nil,
			PartialMetadataObjects: nil,
		},
	}
}

type privateKeyRotationFixture struct {
	t               *testing.T
	builder         *testpkg.Builder
	certificate     *cmapi.Certificate
	temporarySecret string
}

func (f *privateKeyRotationFixture) Reconcile() error {
	f.builder.Init()

	w := &controllerWrapper{}
	if _, _, err := w.Register(f.builder.Context); err != nil {
		return err
	}

	f.builder.Start()
	if err := w.controller.ProcessItem(f.t.Context(), types.NamespacedName{
		Namespace: f.certificate.Namespace,
		Name:      f.certificate.Name,
	}); err != nil {
		return err
	}

	f.builder.Sync()
	return nil
}

func (f *privateKeyRotationFixture) Stop() {
	f.builder.Stop()
}

func (f *privateKeyRotationFixture) Certificate() *cmapi.Certificate {
	crt, err := f.builder.FakeCMClient().CertmanagerV1().Certificates(f.certificate.Namespace).Get(f.t.Context(), f.certificate.Name, metav1.GetOptions{})
	if err != nil {
		f.t.Fatal(err)
	}
	return crt
}

func (f *privateKeyRotationFixture) Secret(name string) (*corev1.Secret, error) {
	return f.builder.FakeKubeClient().CoreV1().Secrets(f.certificate.Namespace).Get(f.t.Context(), name, metav1.GetOptions{})
}

func assertPrivateKeyMatchesSpec(t *testing.T, pkData []byte, spec cmapi.CertificateSpec) {
	t.Helper()

	if len(pkData) == 0 {
		t.Fatal("expected tls.key data to be present")
	}

	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	violations := pki.PrivateKeyMatchesSpec(pk, spec)
	if len(violations) > 0 {
		t.Fatalf("expected private key to match certificate spec, got violations: %v", violations)
	}
}

func TestProcessItem_PrivateKeyRotationFixtures(t *testing.T) {
	validRSA := mustGenerateRSA(t, 2048)
	mismatchedECDSA := mustGenerateECDSA(t, pki.ECCurve256)

	tests := map[string]struct {
		fixture                    *privateKeyRotationFixture
		wantNextPrivateKeySecret   *string
		assertResult               func(t *testing.T, fixture *privateKeyRotationFixture)
	}{
		"if target Secret is missing and rotation policy is Never, generate a new temporary private key": {
			fixture:                  newPrivateKeyRotationFixtureBuilder(t).WithRotationPolicy(cmapi.RotationPolicyNever).Build(),
			wantNextPrivateKeySecret: new("test-notrandom"),
			assertResult: func(t *testing.T, fixture *privateKeyRotationFixture) {
				temporarySecret, err := fixture.Secret(fixture.temporarySecret)
				if err != nil {
					t.Fatal(err)
				}

				assertPrivateKeyMatchesSpec(t, temporarySecret.Data[corev1.TLSPrivateKeyKey], fixture.certificate.Spec)
			},
		},
		"if target Secret private key algorithm mismatches and rotation policy is Never, do not create a temporary private key": {
			fixture: newPrivateKeyRotationFixtureBuilder(t).
				WithRotationPolicy(cmapi.RotationPolicyNever).
				WithTargetSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: mismatchedECDSA}).
				Build(),
			wantNextPrivateKeySecret: nil,
			assertResult: func(t *testing.T, fixture *privateKeyRotationFixture) {
				_, err := fixture.Secret(fixture.temporarySecret)
				if !apierrors.IsNotFound(err) {
					t.Fatalf("expected temporary Secret to not exist, got: %v", err)
				}

				targetSecret, err := fixture.Secret(fixture.certificate.Spec.SecretName)
				if err != nil {
					t.Fatal(err)
				}

				if diff := cmp.Diff(mismatchedECDSA, targetSecret.Data[corev1.TLSPrivateKeyKey]); diff != "" {
					t.Fatalf("unexpected target Secret private key data (-want +got):\n%s", diff)
				}
			},
		},
		"if target Secret contains a matching private key and rotation policy is Never, reuse it in the temporary Secret": {
			fixture: newPrivateKeyRotationFixtureBuilder(t).
				WithRotationPolicy(cmapi.RotationPolicyNever).
				WithTargetSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: validRSA}).
				Build(),
			wantNextPrivateKeySecret: new("test-notrandom"),
			assertResult: func(t *testing.T, fixture *privateKeyRotationFixture) {
				temporarySecret, err := fixture.Secret(fixture.temporarySecret)
				if err != nil {
					t.Fatal(err)
				}

				if diff := cmp.Diff(validRSA, temporarySecret.Data[corev1.TLSPrivateKeyKey]); diff != "" {
					t.Fatalf("unexpected temporary Secret private key data (-want +got):\n%s", diff)
				}
			},
		},
		"if target Secret private key algorithm mismatches and rotation policy is Always, generate a new temporary private key": {
			fixture: newPrivateKeyRotationFixtureBuilder(t).
				WithRotationPolicy(cmapi.RotationPolicyAlways).
				WithTargetSecretData(map[string][]byte{corev1.TLSPrivateKeyKey: mismatchedECDSA}).
				Build(),
			wantNextPrivateKeySecret: new("test-notrandom"),
			assertResult: func(t *testing.T, fixture *privateKeyRotationFixture) {
				temporarySecret, err := fixture.Secret(fixture.temporarySecret)
				if err != nil {
					t.Fatal(err)
				}

				if diff := cmp.Diff(mismatchedECDSA, temporarySecret.Data[corev1.TLSPrivateKeyKey]); diff == "" {
					t.Fatal("expected a regenerated private key in temporary Secret")
				}

				assertPrivateKeyMatchesSpec(t, temporarySecret.Data[corev1.TLSPrivateKeyKey], fixture.certificate.Spec)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.fixture.Reconcile()
			defer test.fixture.Stop()
			if err != nil {
				t.Fatal(err)
			}

			gotCertificate := test.fixture.Certificate()

			if diff := cmp.Diff(test.wantNextPrivateKeySecret, gotCertificate.Status.NextPrivateKeySecretName); diff != "" {
				t.Fatalf("unexpected nextPrivateKeySecretName (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(test.fixture.certificate.Status.Conditions, gotCertificate.Status.Conditions); diff != "" {
				t.Fatalf("unexpected certificate conditions (-want +got):\n%s", diff)
			}

			test.assertResult(t, test.fixture)
		})
	}
}

func TestProcessItem(t *testing.T) {
	ownedSecretWithName := func(namespace, name, owner string, data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				cmapi.IsNextPrivateKeySecretLabelKey:      "true",
				cmapi.PartOfCertManagerControllerLabelKey: "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: owner, UID: types.UID(owner)},
				}, certificateGvk),
			},
		},
			Data: data,
		}
	}
	tests := map[string]struct {
		// key that should be passed to ProcessItem.
		// if not set, the 'namespace/name' of the 'Certificate' field will be used.
		// if neither is set, the key will be ""
		key types.NamespacedName

		// Certificate to be synced for the test.
		// if not set, the 'key' will be passed to ProcessItem instead.
		certificate *cmapi.Certificate

		secrets []runtime.Object

		// Request, if set, will exist in the apiserver before the test is run.
		requests []*cmapi.CertificateRequest

		expectedActions []testpkg.Action

		expectedEvents []string

		// err is the expected error text returned by the controller, if any.
		err string
	}{
		"do nothing if an empty 'key' is used": {},
		"do nothing if an invalid 'key' is used": {
			key: types.NamespacedName{
				Namespace: "abc",
				Name:      "def/ghi",
			},
		},
		"do nothing if a key references a Certificate that does not exist": {
			key: types.NamespacedName{
				Namespace: "namespace",
				Name:      "name",
			},
		},
		"do nothing if Certificate has 'Issuing' condition set to 'false'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionFalse,
						},
					},
				},
			},
		},
		"do nothing if Certificate has no 'Issuing' condition": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{},
				},
			},
		},
		"create a secret and record its name if issuing is true": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "test-notrandom"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("test-notrandom"),
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
							GenerateName:    "test-",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
			},
		},
		"create a secret using the already allocated name if it is set": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "fixed-name"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							Name:            "fixed-name",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
			},
		},
		// TODO: in this case we should adapt the controller behaviour to unset the nextPrivateKeySecretName to
		//  gracefully recover
		"error if an existing Secret exists and is named as status.nextPrivateKeySecretName but it is not owned by the Certificate": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets:        []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "fixed-name"}}},
			expectedEvents: []string{`Normal Generated Stored new private key in temporary Secret resource "fixed-name"`},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewGetAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"testns",
					"test",
				)),
				testpkg.NewCustomMatch(coretesting.NewCreateAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:       "testns",
							Name:            "fixed-name",
							Labels:          map[string]string{cmapi.IsNextPrivateKeySecretLabelKey: "true", cmapi.PartOfCertManagerControllerLabelKey: "true"},
							OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test"}}, certificateGvk)},
						},
						Data: map[string][]byte{"tls.key": nil},
					},
				), relaxedSecretMatcher),
				testpkg.NewAction(coretesting.NewGetAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if multiple owned secrets exist, delete them all": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
			},
		},
		"if multiple owned secrets exist with one matching nextPrivateKeySecretName, preserve the matching one and delete others": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateRSA(t, 2048)}),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
				ownedSecretWithName("testns", "fixed-name-3", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-3",
				)),
			},
		},
		"if multiple owned secrets exist but none match nextPrivateKeySecretName, delete all": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("expected-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
				ownedSecretWithName("testns", "fixed-name-2", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name-2",
				)),
			},
		},
		"if a named and owned secret exists but contains no data, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists but nextPrivateKeySecretName is not set, set it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewUpdateSubresourceAction(
					cmapi.SchemeGroupVersion.WithResource("certificates"),
					"status",
					"testns",
					&cmapi.Certificate{
						ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
						Status: cmapi.CertificateStatus{
							NextPrivateKeySecretName: new("fixed-name"),
							Conditions: []cmapi.CertificateCondition{
								{
									Type:   cmapi.CertificateConditionIssuing,
									Status: cmmeta.ConditionTrue,
								},
							},
						},
					},
				)),
			},
		},
		"if an owned secret exists but has a different name to nextPrivateKeySecretName, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name-2"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", nil),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists but contains invalid private key data, delete it": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": []byte("invalid")}),
			},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists but contains 'non-matching' data, delete it'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateECDSA(t, pki.ECCurve256)}),
			},
			expectedEvents: []string{"Normal Deleted Regenerating private key due to change in fields: [spec.privateKey.algorithm]"},
			expectedActions: []testpkg.Action{
				testpkg.NewAction(coretesting.NewDeleteAction(
					corev1.SchemeGroupVersion.WithResource("secrets"),
					"testns",
					"fixed-name",
				)),
			},
		},
		"if an owned secret exists and contains data valid for the spec, do nothing'": {
			certificate: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "testns", Name: "test", UID: types.UID("test")},
				Status: cmapi.CertificateStatus{
					NextPrivateKeySecretName: new("fixed-name"),
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionIssuing,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			},
			secrets: []runtime.Object{
				ownedSecretWithName("testns", "fixed-name", "test", map[string][]byte{"tls.key": mustGenerateRSA(t, 2048)}),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create and initialise a new unit test builder
			builder := &testpkg.Builder{
				T:               t,
				ExpectedEvents:  test.expectedEvents,
				ExpectedActions: test.expectedActions,
				StringGenerator: func(i int) string { return "notrandom" },
			}
			if test.certificate != nil {
				builder.CertManagerObjects = append(builder.CertManagerObjects, test.certificate)
			}
			if test.secrets != nil {
				builder.KubeObjects = append(builder.KubeObjects, test.secrets...)
			}
			for _, req := range test.requests {
				builder.CertManagerObjects = append(builder.CertManagerObjects, req)
			}
			builder.Init()

			// Register informers used by the controller using the registration wrapper
			w := &controllerWrapper{}
			_, _, err := w.Register(builder.Context)
			if err != nil {
				t.Fatal(err)
			}
			// Start the informers and begin processing updates
			builder.Start()
			defer builder.Stop()

			key := test.key
			if key == (types.NamespacedName{}) && test.certificate != nil {
				key = types.NamespacedName{
					Name:      test.certificate.Name,
					Namespace: test.certificate.Namespace,
				}
			}

			// Call ProcessItem
			err = w.controller.ProcessItem(t.Context(), key)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}

			if err := builder.AllEventsCalled(); err != nil {
				builder.T.Error(err)
			}
			if err := builder.AllActionsExecuted(); err != nil {
				builder.T.Error(err)
			}
		})
	}
}
