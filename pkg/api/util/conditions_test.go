/*
Copyright 2021 The cert-manager Authors.

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
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	testingclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestSetCertificateRequestCondition(t *testing.T) {
	now := time.Now()
	nowMeta := metav1.NewTime(now)

	tests := []struct {
		name          string
		cr            *cmapi.CertificateRequest
		conditionType cmapi.CertificateRequestConditionType
		status        cmmeta.ConditionStatus
		reason        string
		message       string
		expected      *cmapi.CertificateRequest
	}{
		{
			name: "add new Approved condition",
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{},
			},
			conditionType: cmapi.CertificateRequestConditionApproved,
			status:        cmmeta.ConditionTrue,
			reason:        "Approved",
			message:       "Request approved",
			expected: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionApproved,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Approved",
							Message:            "Request approved",
							LastTransitionTime: &nowMeta,
						},
					},
				},
			},
		},
		{
			name: "add new Denied condition",
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{},
			},
			conditionType: cmapi.CertificateRequestConditionDenied,
			status:        cmmeta.ConditionTrue,
			reason:        "Denied",
			message:       "Request denied",
			expected: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionDenied,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Denied",
							Message:            "Request denied",
							LastTransitionTime: &nowMeta,
						},
					},
				},
			},
		},
		{
			name: "update existing Ready=False to Ready=True (state transition)",
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Pending",
							Message:            "Request pending",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionTrue,
			reason:        "Issued",
			message:       "Request issued",
			expected: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionTrue,
							Reason:             "Issued",
							Message:            "Request issued",
							LastTransitionTime: &nowMeta,
						},
					},
				},
			},
		},
		{
			name: "update existing Ready=False with new Reason (no state transition)",
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Pending",
							Message:            "Request pending",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionFalse,
			reason:        "Denied",
			message:       "Request denied",
			expected: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Denied",
							Message:            "Request denied",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
					},
				},
			},
		},
		{
			name: "clean up duplicate conditions of the same type",
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Pending",
							Message:            "Request pending 1",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Pending",
							Message:            "Request pending 2",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionFalse,
			reason:        "Denied",
			message:       "Request denied",
			expected: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             "Denied",
							Message:            "Request denied",
							LastTransitionTime: &metav1.Time{Time: now.Add(-time.Hour)},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Clock = testingclock.NewFakeClock(now)
			defer func() {
				Clock = clock.RealClock{}
			}()

			SetCertificateRequestCondition(tt.cr, tt.conditionType, tt.status, tt.reason, tt.message)

			if !reflect.DeepEqual(tt.cr, tt.expected) {
				t.Errorf("SetCertificateRequestCondition() \n got = %v\n want = %v", tt.cr, tt.expected)
			}
		})
	}
}
