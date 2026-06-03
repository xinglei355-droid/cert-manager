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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// 示例测试，展示如何使用 CertificateRotationTestFixtureBuilder 构建不同场景的测试
func TestCertificateRotationFixtureBuilderExamples(t *testing.T) {
	t.Run("Secret missing scenario", func(t *testing.T) {
		builder := NewCertificateRotationTestFixtureBuilder(t)
		crt, secret := builder.
			WithName("test-cert").
			SecretMissingScenario().
			WithRotationPolicy(cmapi.RotationPolicyAlways).
			Build()
		
		if secret != nil {
			t.Error("expected secret to be nil in Secret missing scenario")
		}
		if crt == nil {
			t.Error("expected certificate to be non-nil")
		}
		if crt.Spec.PrivateKey.RotationPolicy != cmapi.RotationPolicyAlways {
			t.Errorf("expected rotation policy to be Always, got %q", crt.Spec.PrivateKey.RotationPolicy)
		}
	})
	
	t.Run("Secret with wrong algorithm scenario", func(t *testing.T) {
		builder := NewCertificateRotationTestFixtureBuilder(t)
		crt, secret := builder.
			WithName("test-cert").
			WithPrivateKeyAlgorithm(cmapi.RSAKeyAlgorithm).
			SecretWithWrongAlgorithmScenario().
			Build()
		
		if secret == nil {
			t.Error("expected secret to be non-nil in wrong algorithm scenario")
		}
		if crt == nil {
			t.Error("expected certificate to be non-nil")
		}
	})
	
	t.Run("Rotation policy Never scenario", func(t *testing.T) {
		builder := NewCertificateRotationTestFixtureBuilder(t)
		crt, _ := builder.
			WithName("test-cert").
			RotationPolicyNeverScenario().
			Build()
		
		if crt.Spec.PrivateKey.RotationPolicy != cmapi.RotationPolicyNever {
			t.Errorf("expected rotation policy to be Never, got %q", crt.Spec.PrivateKey.RotationPolicy)
		}
	})
	
	t.Run("Rotation policy Always scenario", func(t *testing.T) {
		builder := NewCertificateRotationTestFixtureBuilder(t)
		crt, _ := builder.
			WithName("test-cert").
			RotationPolicyAlwaysScenario().
			Build()
		
		if crt.Spec.PrivateKey.RotationPolicy != cmapi.RotationPolicyAlways {
			t.Errorf("expected rotation policy to be Always, got %q", crt.Spec.PrivateKey.RotationPolicy)
		}
	})
	
	t.Run("Full configuration example", func(t *testing.T) {
		builder := NewCertificateRotationTestFixtureBuilder(t)
		crt, secret := builder.
			WithName("full-config-cert").
			WithNamespace("custom-namespace").
			WithSecretName("custom-secret-name").
			WithPrivateKeyAlgorithm(cmapi.ECDSAKeyAlgorithm).
			WithPrivateKeySize(384).
			WithIssuerRef("custom-issuer").
			WithDNSNames([]string{"custom.example.com", "www.custom.example.com"}).
			RotationPolicyAlwaysScenario().
			WithExpectedCondition(cmmeta.ConditionTrue, "Ready", "Certificate is ready").
			Build()
		
		if crt.Name != "full-config-cert" {
			t.Errorf("expected certificate name to be 'full-config-cert', got %q", crt.Name)
		}
		if crt.Namespace != "custom-namespace" {
			t.Errorf("expected namespace to be 'custom-namespace', got %q", crt.Namespace)
		}
		if crt.Spec.SecretName != "custom-secret-name" {
			t.Errorf("expected secret name to be 'custom-secret-name', got %q", crt.Spec.SecretName)
		}
		if crt.Spec.PrivateKey.Algorithm != cmapi.ECDSAKeyAlgorithm {
			t.Errorf("expected algorithm to be ECDSA, got %q", crt.Spec.PrivateKey.Algorithm)
		}
		if crt.Spec.PrivateKey.Size != 384 {
			t.Errorf("expected key size to be 384, got %d", crt.Spec.PrivateKey.Size)
		}
		if crt.Spec.IssuerRef.Name != "custom-issuer" {
			t.Errorf("expected issuer name to be 'custom-issuer', got %q", crt.Spec.IssuerRef.Name)
		}
		if len(crt.Spec.DNSNames) != 2 {
			t.Errorf("expected 2 DNS names, got %d", len(crt.Spec.DNSNames))
		}
		if secret != nil {
			t.Error("expected secret to be nil in this scenario")
		}
	})
}
