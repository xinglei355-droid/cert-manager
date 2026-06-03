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
	"k8s.io/apimachinery/pkg/types"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// CertificateRotationTestFixtureBuilder 是一个测试构建器，用于构造不同场景下的 Certificate 私钥轮换测试
type CertificateRotationTestFixtureBuilder struct {
	t       *testing.T
	name    string
	namespace string

	// 证书相关配置
	certificateSpec cmapi.CertificateSpec
	issuingCondition bool

	// Secret 相关配置
	secretExists bool
	secretData map[string][]byte
	secretName string

	// 期望结果
	expectedSecretData map[string][]byte
	expectedConditionStatus cmmeta.ConditionStatus
	expectedConditionReason string
	expectedConditionMessage string
}

// NewCertificateRotationTestFixtureBuilder 创建一个新的测试构建器实例
func NewCertificateRotationTestFixtureBuilder(t *testing.T) *CertificateRotationTestFixtureBuilder {
	return &CertificateRotationTestFixtureBuilder{
		t: t,
		name: "test-certificate",
		namespace: "test-namespace",
		issuingCondition: true, // 默认 Issuing 条件为 True
	}
}

// WithName 设置 Certificate 的名称
func (b *CertificateRotationTestFixtureBuilder) WithName(name string) *CertificateRotationTestFixtureBuilder {
	b.name = name
	return b
}

// WithNamespace 设置 Certificate 的命名空间
func (b *CertificateRotationTestFixtureBuilder) WithNamespace(namespace string) *CertificateRotationTestFixtureBuilder {
	b.namespace = namespace
	return b
}

// WithSecretName 设置 Secret 的名称
func (b *CertificateRotationTestFixtureBuilder) WithSecretName(secretName string) *CertificateRotationTestFixtureBuilder {
	b.secretName = secretName
	b.certificateSpec.SecretName = secretName
	return b
}

// WithIssuingCondition 设置是否有 Issuing 条件
func (b *CertificateRotationTestFixtureBuilder) WithIssuingCondition(issuing bool) *CertificateRotationTestFixtureBuilder {
	b.issuingCondition = issuing
	return b
}

// WithPrivateKeyAlgorithm 设置期望的私钥算法
func (b *CertificateRotationTestFixtureBuilder) WithPrivateKeyAlgorithm(algorithm cmapi.PrivateKeyAlgorithm) *CertificateRotationTestFixtureBuilder {
	if b.certificateSpec.PrivateKey == nil {
		b.certificateSpec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	b.certificateSpec.PrivateKey.Algorithm = algorithm
	return b
}

// WithPrivateKeySize 设置期望的私钥大小
func (b *CertificateRotationTestFixtureBuilder) WithPrivateKeySize(size int) *CertificateRotationTestFixtureBuilder {
	if b.certificateSpec.PrivateKey == nil {
		b.certificateSpec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	b.certificateSpec.PrivateKey.Size = size
	return b
}

// WithRotationPolicy 设置私钥轮换策略
func (b *CertificateRotationTestFixtureBuilder) WithRotationPolicy(policy cmapi.PrivateKeyRotationPolicy) *CertificateRotationTestFixtureBuilder {
	if b.certificateSpec.PrivateKey == nil {
		b.certificateSpec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	b.certificateSpec.PrivateKey.RotationPolicy = policy
	return b
}

// WithIssuerRef 设置 Issuer 引用
func (b *CertificateRotationTestFixtureBuilder) WithIssuerRef(name string) *CertificateRotationTestFixtureBuilder {
	b.certificateSpec.IssuerRef = cmmeta.IssuerReference{
		Name: name,
	}
	return b
}

// WithDNSNames 设置 DNS 名称
func (b *CertificateRotationTestFixtureBuilder) WithDNSNames(names []string) *CertificateRotationTestFixtureBuilder {
	b.certificateSpec.DNSNames = names
	return b
}

// WithExistingSecret 设置一个存在的 Secret
func (b *CertificateRotationTestFixtureBuilder) WithExistingSecret(data map[string][]byte) *CertificateRotationTestFixtureBuilder {
	b.secretExists = true
	b.secretData = data
	return b
}

// WithExistingSecretWithMismatchedAlgorithm 设置一个存在但算法不匹配的 Secret
func (b *CertificateRotationTestFixtureBuilder) WithExistingSecretWithMismatchedAlgorithm() *CertificateRotationTestFixtureBuilder {
	b.secretExists = true
	
	// 生成一个不同算法的私钥
	if b.certificateSpec.PrivateKey == nil {
		b.certificateSpec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	
	algorithm := b.certificateSpec.PrivateKey.Algorithm
	if algorithm == "" {
		algorithm = cmapi.RSAKeyAlgorithm
	}
	
	var pkBytes []byte
	if algorithm == cmapi.RSAKeyAlgorithm {
		// 如果期望是 RSA，就生成 ECDSA
		pk, err := pki.GenerateECPrivateKey(pki.ECCurve256)
		if err != nil {
			b.t.Fatal(err)
		}
		pkBytes, err = pki.EncodePKCS8PrivateKey(pk)
		if err != nil {
			b.t.Fatal(err)
		}
	} else {
		// 如果期望是 ECDSA 或其他，就生成 RSA
		pk, err := pki.GenerateRSAPrivateKey(2048)
		if err != nil {
			b.t.Fatal(err)
		}
		pkBytes, err = pki.EncodePKCS8PrivateKey(pk)
		if err != nil {
			b.t.Fatal(err)
		}
	}
	
	b.secretData = map[string][]byte{
		corev1.TLSPrivateKeyKey: pkBytes,
	}
	return b
}

// WithExpectedSecretData 设置期望的 Secret 数据
func (b *CertificateRotationTestFixtureBuilder) WithExpectedSecretData(data map[string][]byte) *CertificateRotationTestFixtureBuilder {
	b.expectedSecretData = data
	return b
}

// WithExpectedCondition 设置期望的 Certificate 条件
func (b *CertificateRotationTestFixtureBuilder) WithExpectedCondition(status cmmeta.ConditionStatus, reason, message string) *CertificateRotationTestFixtureBuilder {
	b.expectedConditionStatus = status
	b.expectedConditionReason = reason
	b.expectedConditionMessage = message
	return b
}

// Build 构建测试 fixture
func (b *CertificateRotationTestFixtureBuilder) Build() (*cmapi.Certificate, *corev1.Secret) {
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.name,
			Namespace: b.namespace,
			UID: types.UID(b.name),
		},
		Spec: b.certificateSpec,
	}
	
	// 设置默认值
	if crt.Spec.SecretName == "" {
		crt.Spec.SecretName = b.name + "-secret"
	}
	if crt.Spec.IssuerRef.Name == "" {
		crt.Spec.IssuerRef.Name = "test-issuer"
	}
	if len(crt.Spec.DNSNames) == 0 {
		crt.Spec.DNSNames = []string{"example.com"}
	}
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	
	// 设置 Issuing 条件
	if b.issuingCondition {
		crt.Status.Conditions = []cmapi.CertificateCondition{
			{
				Type: cmapi.CertificateConditionIssuing,
				Status: cmmeta.ConditionTrue,
			},
		}
	}
	
	var secret *corev1.Secret
	if b.secretExists {
		if b.secretName == "" {
			b.secretName = crt.Spec.SecretName
		}
		
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: b.secretName,
				Namespace: b.namespace,
			},
			Data: b.secretData,
		}
	}
	
	return crt, secret
}

// SecretMissingScenario 创建一个 Secret 缺失场景
func (b *CertificateRotationTestFixtureBuilder) SecretMissingScenario() *CertificateRotationTestFixtureBuilder {
	b.secretExists = false
	b.secretData = nil
	return b
}

// SecretWithWrongAlgorithmScenario 创建一个 Secret 中私钥算法不匹配的场景
func (b *CertificateRotationTestFixtureBuilder) SecretWithWrongAlgorithmScenario() *CertificateRotationTestFixtureBuilder {
	return b.WithExistingSecretWithMismatchedAlgorithm()
}

// RotationPolicyNeverScenario 创建一个 rotationPolicy=Never 的场景
func (b *CertificateRotationTestFixtureBuilder) RotationPolicyNeverScenario() *CertificateRotationTestFixtureBuilder {
	return b.WithRotationPolicy(cmapi.RotationPolicyNever)
}

// RotationPolicyAlwaysScenario 创建一个 rotationPolicy=Always 的场景
func (b *CertificateRotationTestFixtureBuilder) RotationPolicyAlwaysScenario() *CertificateRotationTestFixtureBuilder {
	return b.WithRotationPolicy(cmapi.RotationPolicyAlways)
}

// ValidateSecretData 验证 Secret 数据是否符合预期
func (b *CertificateRotationTestFixtureBuilder) ValidateSecretData(t *testing.T, actualSecret *corev1.Secret) {
	if b.expectedSecretData == nil {
		// 如果没有设置期望数据，只需要验证 key 存在
		if actualSecret.Data != nil && len(actualSecret.Data[corev1.TLSPrivateKeyKey]) > 0 {
			return
		}
		t.Error("expected secret to contain private key data")
		return
	}
	
	for key, expectedValue := range b.expectedSecretData {
		actualValue, ok := actualSecret.Data[key]
		if !ok {
			t.Errorf("expected secret to have key %q, but it was missing", key)
			continue
		}
		// 对于私钥，我们只验证其存在性和类型，而不验证具体值
		if key == corev1.TLSPrivateKeyKey {
			// 尝试解析私钥，验证其有效性
			_, err := pki.DecodePrivateKeyBytes(actualValue)
			if err != nil {
				t.Errorf("failed to decode private key: %v", err)
			}
		} else {
			if string(actualValue) != string(expectedValue) {
				t.Errorf("unexpected value for key %q: expected %q, got %q", key, string(expectedValue), string(actualValue))
			}
		}
	}
}

// ValidateCertificateCondition 验证 Certificate 条件是否符合预期
func (b *CertificateRotationTestFixtureBuilder) ValidateCertificateCondition(t *testing.T, actualCert *cmapi.Certificate, conditionType cmapi.CertificateConditionType) {
	// 找到指定类型的条件
	var foundCondition *cmapi.CertificateCondition
	for _, c := range actualCert.Status.Conditions {
		if c.Type == conditionType {
			foundCondition = &c
			break
		}
	}
	
	if b.expectedConditionStatus == "" {
		// 如果没有设置期望状态，就不需要验证
		return
	}
	
	if foundCondition == nil {
		t.Errorf("expected condition of type %q to be present, but it was not found", conditionType)
		return
	}
	
	if foundCondition.Status != b.expectedConditionStatus {
		t.Errorf("unexpected condition status for type %q: expected %q, got %q", 
			conditionType, b.expectedConditionStatus, foundCondition.Status)
	}
	
	if b.expectedConditionReason != "" && foundCondition.Reason != b.expectedConditionReason {
		t.Errorf("unexpected condition reason for type %q: expected %q, got %q", 
			conditionType, b.expectedConditionReason, foundCondition.Reason)
	}
	
	if b.expectedConditionMessage != "" && foundCondition.Message != b.expectedConditionMessage {
		t.Logf("condition message for type %q: got %q", conditionType, foundCondition.Message)
	}
}
