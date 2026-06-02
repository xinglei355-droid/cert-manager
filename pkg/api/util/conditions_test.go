
package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestSetCertificateRequestCondition(t *testing.T) {
	testCases := []struct {
		name             string
		initialCR        *cmapi.CertificateRequest
		conditionType    cmapi.CertificateRequestConditionType
		status           cmmeta.ConditionStatus
		reason           string
		message          string
		expectedCR       *cmapi.CertificateRequest
		expectTransition bool
	}{
		{
			name: "添加新的 Approved 条件",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
			},
			conditionType: cmapi.CertificateRequestConditionApproved,
			status:        cmmeta.ConditionTrue,
			reason:        "cert-manager.io",
			message:       "已批准",
			expectTransition: true,
		},
		{
			name: "添加新的 Denied 条件",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
			},
			conditionType: cmapi.CertificateRequestConditionDenied,
			status:        cmmeta.ConditionTrue,
			reason:        "cert-manager.io",
			message:       "已拒绝",
			expectTransition: true,
		},
		{
			name: "添加新的 Ready=False 条件",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionFalse,
			reason:        cmapi.CertificateRequestReasonPending,
			message:       "等待中",
			expectTransition: true,
		},
		{
			name: "添加新的 Ready=True 条件",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionTrue,
			reason:        cmapi.CertificateRequestReasonIssued,
			message:       "已颁发",
			expectTransition: true,
		},
		{
			name: "更新现有条件，状态相同",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             cmapi.CertificateRequestReasonPending,
							Message:            "等待中",
							LastTransitionTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionFalse,
			reason:        cmapi.CertificateRequestReasonPending,
			message:       "更新等待中",
			expectTransition: false, // 状态相同，不应该更新 LastTransitionTime
		},
		{
			name: "更新现有条件，状态不同",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             cmapi.CertificateRequestReasonPending,
							Message:            "等待中",
							LastTransitionTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionTrue,
			reason:        cmapi.CertificateRequestReasonIssued,
			message:       "已颁发",
			expectTransition: true, // 状态不同，应该更新 LastTransitionTime
		},
		{
			name: "修复重复条件的问题",
			initialCR: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cr"},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type:               cmapi.CertificateRequestConditionReady,
							Status:             cmmeta.ConditionFalse,
							Reason:             cmapi.CertificateRequestReasonPending,
							Message:            "等待中 1",
							LastTransitionTime: &metav1.Time{Time: time.Now().Add(-2 * time.Hour)},
						},
						{
							Type:               cmapi.CertificateRequestConditionReady, // 重复的条件！
							Status:             cmmeta.ConditionFalse,
							Reason:             cmapi.CertificateRequestReasonFailed,
							Message:            "失败了 2",
							LastTransitionTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
						},
						{
							Type:               cmapi.CertificateRequestConditionApproved, // 另一个类型的条件，应该保留
							Status:             cmmeta.ConditionTrue,
							Reason:             "cert-manager.io",
							Message:            "已批准",
							LastTransitionTime: &metav1.Time{Time: time.Now().Add(-3 * time.Hour)},
						},
					},
				},
			},
			conditionType: cmapi.CertificateRequestConditionReady,
			status:        cmmeta.ConditionTrue,
			reason:        cmapi.CertificateRequestReasonIssued,
			message:       "已颁发",
			expectTransition: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 设置固定时钟
			fixedClock := testing.NewFakeClock(time.Now())
			Clock = fixedClock

			// 复制初始 CR 以避免影响其他测试
			cr := tc.initialCR.DeepCopy()

			// 调用函数
			SetCertificateRequestCondition(cr, tc.conditionType, tc.status, tc.reason, tc.message)

			// 验证结果
			assert.Len(t, cr.Status.Conditions, len(tc.initialCR.Status.Conditions)-countDuplicateConditions(tc.initialCR, tc.conditionType)+1)

			// 检查新添加或更新的条件
			found := false
			for _, cond := range cr.Status.Conditions {
				if cond.Type == tc.conditionType {
					found = true
					assert.Equal(t, tc.status, cond.Status)
					assert.Equal(t, tc.reason, cond.Reason)
					assert.Equal(t, tc.message, cond.Message)

					if tc.expectTransition {
						// 状态变更了，LastTransitionTime 应该是当前固定时间
						assert.Equal(t, metav1.NewTime(fixedClock.Now()), *cond.LastTransitionTime)
					} else {
						// 状态未变更，LastTransitionTime 应该保持原样
						originalCond := findCondition(tc.initialCR, tc.conditionType)
						if originalCond != nil {
							assert.Equal(t, originalCond.LastTransitionTime, cond.LastTransitionTime)
						}
					}
				} else {
					// 其他类型的条件应该保持不变
					originalCond := findCondition(tc.initialCR, cond.Type)
					if originalCond != nil {
						assert.Equal(t, *originalCond, cond)
					}
				}
			}
			assert.True(t, found, "应该找到设置的条件")
		})
	}
}

// 辅助函数：计算初始 CR 中特定类型条件的数量
func countDuplicateConditions(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType) int {
	count := 0
	for _, cond := range cr.Status.Conditions {
		if cond.Type == conditionType {
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return count // 返回所有匹配的条件数，它们会被替换为 1 个新条件
}

// 辅助函数：在 CR 中查找特定类型的第一个条件
func findCondition(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType) *cmapi.CertificateRequestCondition {
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == conditionType {
			return &cr.Status.Conditions[i]
		}
	}
	return nil
}
