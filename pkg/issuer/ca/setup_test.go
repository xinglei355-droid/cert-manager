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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestCA_Setup_ConditionMessageKeepsRootCause(t *testing.T) {
	notFoundErr := apierrors.NewNotFound(corev1.Resource("secrets"), "ca-key-pair")
	wrappedErr := fmt.Errorf("failed to fetch CA bundle: %w", notFoundErr)
	issuer := &v1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "test-namespace",
		},
		Spec: v1.IssuerSpec{
			IssuerConfig: v1.IssuerConfig{
				CA: &v1.CAIssuer{SecretName: "ca-key-pair"},
			},
		},
	}
	recorder := &controllertest.FakeRecorder{}
	caIssuer := &CA{
		Context: &controller.Context{Recorder: recorder},
		secretsLister: testlisters.NewFakeSecretLister(
			testlisters.SetFakeSecretNamespaceListerGet(nil, wrappedErr),
		),
	}

	err := caIssuer.Setup(t.Context(), issuer)
	require.Error(t, err)
	assert.EqualError(t, err, wrappedErr.Error())
	require.Len(t, issuer.Status.Conditions, 1)
	assert.Equal(t, v1.IssuerConditionReady, issuer.Status.Conditions[0].Type)
	assert.Equal(t, cmmeta.ConditionFalse, issuer.Status.Conditions[0].Status)
	assert.Equal(t, errorGetKeyPair, issuer.Status.Conditions[0].Reason)
	assert.Equal(t, messageErrorGetKeyPair+cmerrors.RootCause(wrappedErr).Error(), issuer.Status.Conditions[0].Message)
	require.Len(t, recorder.Events, 1)
	assert.Equal(t, fmt.Sprintf("%s %s %s", corev1.EventTypeWarning, errorGetKeyPair, messageErrorGetKeyPair+wrappedErr.Error()), recorder.Events[0])
}
