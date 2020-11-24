package rules

import (
	"testing"

	promresourcesv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/prometheus/rules"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
	"kubesphere.io/kubesphere/pkg/simple/client/customalerting"
)

func TestMixAlertingRules(t *testing.T) {
	var tests = []struct {
		description          string
		ruleNamespace        string
		promRuleResources    []*promresourcesv1.PrometheusRule
		thanosRuleResources  []*promresourcesv1.PrometheusRule
		promCliRuleGroups    []*customalerting.RuleGroup
		thanosCliRuleGroups  []*customalerting.RuleGroup
		hasPromRuler         bool
		hasThanosRuler       bool
		level                v1alpha1.RuleLevel
		promRulerExtLabels   func() map[string]string
		thanosRulerExtLabels func() map[string]string
		expected             []*v1alpha1.AlertingRule
	}{{
		description:    "mix custom rules",
		ruleNamespace:  "test",
		hasThanosRuler: true,
		thanosRuleResources: []*promresourcesv1.PrometheusRule{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "custom-alerting-rule-jqbgn",
				Labels: map[string]string{
					"thanosruler":                "thanos-ruler",
					"role":                       "thanos-alerting-rules",
					"custom-alerting-rule-level": "namespace",
				},
			},
			Spec: promresourcesv1.PrometheusRuleSpec{
				Groups: []promresourcesv1.RuleGroup{{
					Name: "alerting.custom.defaults",
					Rules: []promresourcesv1.Rule{{
						Alert: "TestCPUUsageHigh",
						Expr:  intstr.FromString(`namespace:workload_cpu_usage:sum{namespace="test"} > 1`),
						For:   "1m",
					}},
				}},
			},
		}},
		thanosCliRuleGroups: []*customalerting.RuleGroup{{
			Name: "alerting.custom.defaults",
			File: "/etc/thanos/rules/thanos-ruler-thanos-ruler-rulefiles-0/test-custom-alerting-rule-jqbgn.yaml",
			Rules: []*customalerting.AlertingRule{{
				Name:     "TestCPUUsageHigh",
				Query:    `namespace:workload_cpu_usage:sum{namespace="test"} > 1`,
				Duration: 60,
				Health:   string(rules.HealthGood),
				State:    stateInactiveString,
			}},
		}},
		expected: []*v1alpha1.AlertingRule{{
			Id:       "f1e5fa3dd05ab00c-cbf29ce484222325",
			Name:     "TestCPUUsageHigh",
			Query:    `namespace:workload_cpu_usage:sum{namespace="test"} > 1`,
			Health:   string(rules.HealthGood),
			State:    stateInactiveString,
			Duration: "1m",
			Custom:   true,
		}},
	}}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			rules, err := MixAlertingRules(
				test.ruleNamespace,
				test.promRuleResources,
				test.thanosRuleResources,
				test.promCliRuleGroups,
				test.thanosCliRuleGroups,
				test.level,
				test.hasPromRuler,
				test.hasThanosRuler,
				test.promRulerExtLabels,
				test.thanosRulerExtLabels)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(rules, test.expected); diff != "" {
				t.Fatalf("%T differ (-got, +want): %s", test.expected, diff)
			}
		})
	}
}
