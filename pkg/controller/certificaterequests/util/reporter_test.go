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

package util

import (
	"errors"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/test/testutil"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllertest "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = clocktesting.NewFakeClock(fixedClockStart)
)

type reporterT struct {
	certificateRequest *cmapi.CertificateRequest

	err             error
	message, reason string

	call string

	expectedEvents      []string
	expectedConditions  []cmapi.CertificateRequestCondition
	expectedFailureTime *metav1.Time
}

func TestReporter(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)
	oldMetaTime := metav1.NewTime(time.Time{})

	baseCR := gen.CertificateRequest("test")

	exampleErr := errors.New("this is an error")
	exampleMessage := "this is a message"
	exampleReason := "ThisIsAReason"

	failedCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Reason:             "Failed",
		Message:            exampleMessage + ": " + exampleErr.Error(),
		Status:             "False",
		LastTransitionTime: &nowMetaTime,
	}

	invalidRequestCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionInvalidRequest,
		Status:             "True",
		Reason:             "InvalidRequest Reason",
		Message:            "InvalidRequest Message",
		LastTransitionTime: &nowMetaTime,
	}

	pendingCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Reason:             "Pending",
		Message:            exampleMessage + ": " + exampleErr.Error(),
		Status:             "False",
		LastTransitionTime: &nowMetaTime,
	}

	existingPendingCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Reason:             "Pending",
		Message:            "Existing Pending Message",
		Status:             "False",
		LastTransitionTime: &nowMetaTime,
	}

	readyCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Reason:             "Issued",
		Message:            "Certificate fetched from issuer successfully",
		Status:             "True",
		LastTransitionTime: &nowMetaTime,
	}

	deniedReadyCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Reason:             "Denied",
		Message:            "The CertificateRequest was denied by an approval controller",
		Status:             "False",
		LastTransitionTime: &nowMetaTime,
	}

	tests := map[string]reporterT{
		"a failed report should update the conditions and set FailureTime as it is nil": {
			certificateRequest: gen.CertificateRequestFrom(baseCR),
			err:                exampleErr,
			message:            exampleMessage,
			reason:             exampleReason,

			expectedEvents: []string{
				"Warning ThisIsAReason this is a message: this is an error",
			},
			expectedConditions:  []cmapi.CertificateRequestCondition{failedCondition},
			expectedFailureTime: &nowMetaTime,

			call: "failed",
		},

		"a failed report should update the conditions and not FailureTime as it is not nil": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			err:     exampleErr,
			message: exampleMessage,
			reason:  exampleReason,

			expectedEvents: []string{
				"Warning ThisIsAReason this is a message: this is an error",
			},
			expectedConditions:  []cmapi.CertificateRequestCondition{failedCondition},
			expectedFailureTime: &oldMetaTime,

			call: "failed",
		},

		"a report with invalid request should update the conditions and set FailureTime as it is nil": {
			certificateRequest: gen.CertificateRequestFrom(baseCR),
			err:                nil,
			message:            "InvalidRequest Message",
			reason:             "InvalidRequest Reason",

			expectedEvents:      []string{},
			expectedConditions:  []cmapi.CertificateRequestCondition{invalidRequestCondition},
			expectedFailureTime: nil,

			call: "invalid-request",
		},

		"a pending report should update the conditions and send an event as a Pending condition already exists": {
			certificateRequest: gen.CertificateRequestFrom(baseCR),
			err:                exampleErr,
			message:            exampleMessage,
			reason:             exampleReason,

			expectedEvents: []string{
				"Normal ThisIsAReason this is a message: this is an error",
			},
			expectedConditions:  []cmapi.CertificateRequestCondition{pendingCondition},
			expectedFailureTime: nil,

			call: "pending",
		},

		"a pending report should update the conditions and not send an event as a Pending condition already exists": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(existingPendingCondition),
			),
			err:     exampleErr,
			message: exampleMessage,
			reason:  exampleReason,

			// No event sent
			expectedEvents:      []string{},
			expectedConditions:  []cmapi.CertificateRequestCondition{pendingCondition},
			expectedFailureTime: nil,

			call: "pending",
		},
		"a pending report should update the conditions and send an event as only a non Pending condition already exists": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(failedCondition),
			),
			err:     exampleErr,
			message: exampleMessage,
			reason:  exampleReason,

			expectedEvents: []string{
				"Normal ThisIsAReason this is a message: this is an error",
			},
			expectedConditions:  []cmapi.CertificateRequestCondition{pendingCondition},
			expectedFailureTime: nil,

			call: "pending",
		},
		"a ready report should update the conditions and send an event": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(readyCondition),
			),
			expectedEvents: []string{
				"Normal CertificateIssued Certificate fetched from issuer successfully",
			},
			expectedConditions:  []cmapi.CertificateRequestCondition{readyCondition},
			expectedFailureTime: nil,

			call: "ready",
		},

		"a denied report should update the Ready condition to 'Denied'": {
			certificateRequest:  gen.CertificateRequestFrom(baseCR),
			expectedEvents:      []string{},
			expectedConditions:  []cmapi.CertificateRequestCondition{deniedReadyCondition},
			expectedFailureTime: &nowMetaTime,

			call: "denied",
		},

		"a denied report should update the Ready condition to 'Denied', but not update failure time existing": {
			certificateRequest: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(deniedReadyCondition),
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			expectedEvents:      []string{},
			expectedConditions:  []cmapi.CertificateRequestCondition{deniedReadyCondition},
			expectedFailureTime: &oldMetaTime,

			call: "denied",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			apiutil.Clock = fixedClock
			test.runTest(t)
		})
	}
}

func TestReporterStateTransitions(t *testing.T) {
	nowMetaTime := metav1.NewTime(fixedClockStart)
	laterMetaTime := metav1.NewTime(fixedClockStart.Add(1 * time.Second))

	baseCR := gen.CertificateRequest("test")

	approvedCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionApproved,
		Status:             cmmeta.ConditionTrue,
		Reason:             "cert-manager.io",
		Message:            "Certificate request has been approved by cert-manager.io",
		LastTransitionTime: &nowMetaTime,
	}

	deniedCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionDenied,
		Status:             cmmeta.ConditionTrue,
		Reason:             "cert-manager.io",
		Message:            "Certificate request has been denied by cert-manager.io",
		LastTransitionTime: &nowMetaTime,
	}

	pendingCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             "Pending",
		Message:            "Referenced issuer not found",
		LastTransitionTime: &nowMetaTime,
	}

	failedCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             "Failed",
		Message:            "Failed to decode certificate: error",
		LastTransitionTime: &laterMetaTime,
	}

	deniedReadyCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             "Denied",
		Message:            "The CertificateRequest was denied by an approval controller",
		LastTransitionTime: &nowMetaTime,
	}

	readyCondition := cmapi.CertificateRequestCondition{
		Type:               cmapi.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionTrue,
		Reason:             "Issued",
		Message:            "Certificate fetched from issuer successfully",
		LastTransitionTime: &laterMetaTime,
	}

	tests := map[string]struct {
		cr                *cmapi.CertificateRequest
		steps             []func(*Reporter, *cmapi.CertificateRequest)
		expectedEvents    []string
		expectedCondition []cmapi.CertificateRequestCondition
	}{
		"Approved condition is set and remains unchanged when Ready condition transitions": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(approvedCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					r.Pending(cr, nil, "IssuerNotFound", "Referenced issuer not found")
				},
			},
			expectedEvents: []string{
				"Normal IssuerNotFound Referenced issuer not found",
			},
			expectedCondition: []cmapi.CertificateRequestCondition{
				approvedCondition,
				pendingCondition,
			},
		},
		"Denied condition is set alongside Ready=False/Denied": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(deniedCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					r.Denied(cr)
				},
			},
			expectedEvents: []string{},
			expectedCondition: []cmapi.CertificateRequestCondition{
				deniedCondition,
				deniedReadyCondition,
			},
		},
		"Ready=False transitions from Pending to Failed overwrites condition and updates LastTransitionTime": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(pendingCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					fixedClock.SetTime(fixedClockStart.Add(1 * time.Second))
					apiutil.Clock = fixedClock
					r.Failed(cr, errors.New("error"), "Failed", "Failed to decode certificate")
				},
			},
			expectedEvents: []string{
				"Warning Failed Failed to decode certificate: error",
			},
			expectedCondition: []cmapi.CertificateRequestCondition{
				failedCondition,
			},
		},
		"Ready=False transitions from Pending to Denied overwrites condition and updates LastTransitionTime": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(pendingCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					fixedClock.SetTime(fixedClockStart.Add(1 * time.Second))
					apiutil.Clock = fixedClock
					r.Denied(cr)
				},
			},
			expectedEvents: []string{},
			expectedCondition: []cmapi.CertificateRequestCondition{
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Denied",
					Message:            "The CertificateRequest was denied by an approval controller",
					LastTransitionTime: &laterMetaTime,
				},
			},
		},
		"Ready=False to Ready=True transition overwrites condition and updates LastTransitionTime": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(pendingCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					fixedClock.SetTime(fixedClockStart.Add(1 * time.Second))
					apiutil.Clock = fixedClock
					r.Ready(cr)
				},
			},
			expectedEvents: []string{
				"Normal CertificateIssued Certificate fetched from issuer successfully",
			},
			expectedCondition: []cmapi.CertificateRequestCondition{
				readyCondition,
			},
		},
		"Ready=True to Ready=False transition overwrites condition and updates LastTransitionTime": {
			cr: gen.CertificateRequestFrom(baseCR,
				gen.SetCertificateRequestStatusCondition(readyCondition),
			),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					fixedClock.SetTime(fixedClockStart.Add(2 * time.Second))
					apiutil.Clock = fixedClock
					r.Failed(cr, errors.New("error"), "Failed", "Failed to decode certificate")
				},
			},
			expectedEvents: []string{
				"Warning Failed Failed to decode certificate: error",
			},
			expectedCondition: []cmapi.CertificateRequestCondition{
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Failed",
					Message:            "Failed to decode certificate: error",
					LastTransitionTime: &metav1.Time{Time: fixedClockStart.Add(2 * time.Second)},
				},
			},
		},
		"multiple calls to same method do not duplicate conditions": {
			cr: gen.CertificateRequestFrom(baseCR),
			steps: []func(*Reporter, *cmapi.CertificateRequest){
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					r.Pending(cr, nil, "IssuerNotFound", "first call")
				},
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					r.Pending(cr, nil, "IssuerNotFound", "second call")
				},
				func(r *Reporter, cr *cmapi.CertificateRequest) {
					r.Pending(cr, nil, "IssuerNotFound", "third call")
				},
			},
			expectedEvents: []string{
				"Normal IssuerNotFound first call",
			},
			expectedCondition: []cmapi.CertificateRequestCondition{
				{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             "Pending",
					Message:            "third call",
					LastTransitionTime: &nowMetaTime,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixedClock.SetTime(fixedClockStart)
			apiutil.Clock = fixedClock
			recorder := new(controllertest.FakeRecorder)
			reporter := NewReporter(fixedClock, recorder)

			for _, step := range test.steps {
				step(reporter, test.cr)
			}

			if diffErr := testutil.Diff(test.expectedCondition, test.cr.Status.Conditions); diffErr != nil {
				t.Errorf("unexpected conditions:\n%s", diffErr)
			}

			if !slices.Equal(test.expectedEvents, recorder.Events) {
				t.Errorf("unexpected events, exp=%+v got=%+v",
					test.expectedEvents, recorder.Events)
			}
		})
	}
}

func (tt *reporterT) runTest(t *testing.T) {
	recorder := new(controllertest.FakeRecorder)
	reporter := NewReporter(fixedClock, recorder)

	switch tt.call {
	case "failed":
		reporter.Failed(tt.certificateRequest, tt.err,
			tt.reason, tt.message)
	case "invalid-request":
		reporter.InvalidRequest(tt.certificateRequest, tt.reason, tt.message)
	case "pending":
		reporter.Pending(tt.certificateRequest, tt.err,
			tt.reason, tt.message)
	case "denied":
		reporter.Denied(tt.certificateRequest)
	default:
		reporter.Ready(tt.certificateRequest)
	}

	if diffErr := testutil.Diff(tt.expectedConditions, tt.certificateRequest.Status.Conditions); diffErr != nil {
		t.Errorf("got unexpected conditions response: %v", diffErr)
	}

	if !slices.Equal(tt.expectedEvents, recorder.Events) {
		t.Errorf("got unexpected events, exp=%+v got=%+v",
			tt.expectedEvents, recorder.Events)
	}

	if tt.expectedFailureTime == nil {
		if tt.certificateRequest.Status.FailureTime != nil {
			t.Errorf("got unexpected failure time, exp=nil got=%+v",
				tt.certificateRequest.Status.FailureTime)
		}

	} else {
		if tt.certificateRequest.Status.FailureTime.String() !=
			tt.expectedFailureTime.String() {
			t.Errorf("got unexpected failure time, exp=%+v got=%+v",
				tt.expectedFailureTime.String(),
				tt.certificateRequest.Status.FailureTime.String())
		}
	}
}
