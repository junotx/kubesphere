package rules

import (
	"path/filepath"
	"strings"
	"time"

	promresourcesv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/pkg/errors"
	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	prommodel "github.com/prometheus/common/model"
	promlabels "github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/rules"
	"kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
	"kubesphere.io/kubesphere/pkg/simple/client/customalerting"
)

const ErrGenRuleId = "error generating rule id"

func hyphenJoin(elems ...string) string {
	return strings.Join(elems, "-")
}

func slashJoin(elems ...string) string {
	return strings.Join(elems, "/")
}

func FormatExpr(expr string) (string, error) {
	parsedExpr, err := parser.ParseExpr(expr)
	if err == nil {
		return parsedExpr.String(), nil
	}
	return "", errors.Wrapf(err, "failed to parse expr: %s", expr)
}

// InjectExprNamespaceLabel injects an label, whose name is "namespace" and whose value is the specified namespace,
// into the prometheus query expression, which will limit the query scope.
func InjectExprNamespaceLabel(expr, namespace string) (string, error) {
	parsedExpr, err := parser.ParseExpr(expr)
	if err != nil {
		return "", err
	}
	if err = injectproxy.NewEnforcer(&promlabels.Matcher{
		Type:  promlabels.MatchEqual,
		Name:  "namespace",
		Value: namespace,
	}).EnforceNode(parsedExpr); err == nil {
		return parsedExpr.String(), nil
	}
	return "", err
}

func FormatDuration(for_ string) (string, error) {
	var duration prommodel.Duration
	var err error
	if for_ != "" {
		duration, err = prommodel.ParseDuration(for_)
		if err != nil {
			return "", errors.Wrapf(err, "failed to parse Duration string(\"%s\") to time.Duration", for_)
		}
	}
	return duration.String(), nil
}

func parseDurationSeconds(durationSeconds float64) string {
	return prommodel.Duration(int64(durationSeconds * float64(time.Second))).String()
}

// genRuleId generates rule id, which consists of two parts, the first part is the fingerprint generated from the
// properties including group, name, query, duration, and the second part is the fingerprint generated from the labels.
func genRuleId(propsMap, labelsMap map[string]string) string {
	return hyphenJoin(
		prommodel.Fingerprint(prommodel.LabelsToSignature(propsMap)).String(),
		prommodel.Fingerprint(prommodel.LabelsToSignature(labelsMap)).String())
}

// GenResRuleId generates rule id for the rule which is in prometheusrule custom resources
func GenResRuleId(group string, rule *promresourcesv1.Rule) (string, error) {
	if rule.Alert == "" {
		return "", errors.New("invalid alerting rule with empty alert name")
	}
	query, err := FormatExpr(rule.Expr.String())
	if err != nil {
		return "", err
	}
	duration, err := FormatDuration(rule.For)
	if err != nil {
		return "", err
	}
	return genRuleId(map[string]string{
		"group":    group,
		"name":     rule.Alert,
		"query":    query,
		"duration": duration,
	}, rule.Labels), nil
}

// GenCliRuleId generates rule id for the rule from the prometheus or thanos ruler endpoints
func GenCliRuleId(group string, rule *customalerting.AlertingRule,
	externalLabels func() map[string]string) (string, error) {
	query, err := FormatExpr(rule.Query)
	if err != nil {
		return "", err
	}
	duration := parseDurationSeconds(rule.Duration)

	var labelsMap map[string]string
	if externalLabels == nil {
		labelsMap = rule.Labels
	} else {
		labelsMap = make(map[string]string)
		extLabels := externalLabels()
		for key, value := range rule.Labels {
			if v, ok := extLabels[key]; !(ok && value == v) {
				labelsMap[key] = value
			}
		}
	}

	return genRuleId(map[string]string{
		"group":    group,
		"name":     rule.Name,
		"query":    query,
		"duration": duration,
	}, labelsMap), nil
}

// GenApiRuleId generates rule id for the rule added or modified from ui
func GenApiRuleId(group string, rule *v1alpha1.AlertingRule) (string, error) {
	query, err := FormatExpr(rule.Query)
	if err != nil {
		return "", err
	}
	duration, err := FormatDuration(rule.Duration)
	if err != nil {
		return "", err
	}
	return genRuleId(map[string]string{
		"group":    group,
		"name":     rule.Name,
		"query":    query,
		"duration": duration,
	}, rule.Labels), nil
}

// FindCliRule finds the rule with the specified id from the rules
func FindCliRule(cliRuleGroups []*customalerting.RuleGroup, id string,
	extLabels func() map[string]string) (*customalerting.AlertingRule, error) {
	for _, g := range cliRuleGroups {
		for _, r := range g.Rules {
			rid, err := GenCliRuleId(g.Name, r, extLabels)
			if err != nil {
				return nil, errors.Wrap(err, ErrGenRuleId)
			}
			if rid == id {
				return r, nil
			}
		}
	}
	return nil, nil
}

// MixAlertingRules mix rules from custom resources and rules from endpoints. for prometheus, if the prometheus custom
// resource exists, use rules from prometheusrule custom resources as the main reference, otherwise use only rules from
// prometheus endpoint. for thanos ruler, if the thanosruler custom resource exists, the operation is same to prometheus,
// but when it not exists, the rules from thanos ruler endpoint will be ignored.
func MixAlertingRules(
	ruleNamespace string,
	promRuleResources []*promresourcesv1.PrometheusRule,
	thanosRuleResources []*promresourcesv1.PrometheusRule,
	promCliRuleGroups []*customalerting.RuleGroup,
	thanosCliRuleGroups []*customalerting.RuleGroup,
	level v1alpha1.RuleLevel,
	hasPromRuler bool,
	hasThanosRuler bool,
	promRulerExtLabels func() map[string]string,
	thanosRulerExtLabels func() map[string]string) ([]*v1alpha1.AlertingRule, error) {

	var rules = make(map[string]*v1alpha1.AlertingRule)

	mix := func(ruleResources []*promresourcesv1.PrometheusRule, cliRuleGroups []*customalerting.RuleGroup,
		custom bool, externalLabels func() map[string]string) error {
		var (
			// store qualifiers(namespace+"/"+name) of prometheus rule resources
			// in order to locate rules from the endpoint
			ruleResourceSet = make(map[string]struct{})

			cliRules = make(map[string]*customalerting.AlertingRule)
		)
		for _, res := range ruleResources {
			ruleResourceSet[slashJoin(res.Namespace, res.Name)] = struct{}{}
		}
		for _, group := range cliRuleGroups {
			fileShort := strings.TrimSuffix(filepath.Base(group.File), filepath.Ext(group.File))
			if !strings.HasPrefix(fileShort, ruleNamespace+"-") {
				continue
			}
			if _, ok := ruleResourceSet[slashJoin(ruleNamespace, strings.TrimPrefix(fileShort, ruleNamespace+"-"))]; !ok {
				continue
			}
			for _, rule := range group.Rules {
				if cid, err := GenCliRuleId(group.Name, rule, externalLabels); err != nil {
					return errors.Wrap(err, ErrGenRuleId)
				} else {
					cliRules[cid] = rule
				}
			}
		}
		for _, res := range ruleResources {
			for _, g := range res.Spec.Groups {
				for _, resRule := range g.Rules {
					if resRule.Alert == "" {
						continue
					}
					if rid, err := GenResRuleId(g.Name, &resRule); err != nil {
						return errors.Wrap(err, ErrGenRuleId)
					} else {
						if r := MixAlertingRule(rid, &resRule, cliRules[rid], custom, level); r != nil {
							rules[rid] = r
						}
					}
				}
			}
		}
		return nil
	}

	if hasThanosRuler {
		if err := mix(thanosRuleResources, thanosCliRuleGroups, true, thanosRulerExtLabels); err != nil {
			return nil, err
		}
	}
	if hasPromRuler {
		if err := mix(promRuleResources, promCliRuleGroups, false, promRulerExtLabels); err != nil {
			return nil, err
		}
	} else {
		for _, group := range promCliRuleGroups {
			for _, rule := range group.Rules {
				if cid, err := GenCliRuleId(group.Name, rule, nil); err != nil {
					return nil, errors.Wrap(err, ErrGenRuleId)
				} else {
					if r := MixAlertingRule(cid, nil, rule, false, level); r != nil {
						rules[cid] = r
					}
				}
			}
		}
	}

	var ret []*v1alpha1.AlertingRule
	for _, r := range rules {
		ret = append(ret, r)
	}
	return ret, nil
}

func MixAlertingRule(id string, resRule *promresourcesv1.Rule, cliRule *customalerting.AlertingRule,
	custom bool, level v1alpha1.RuleLevel) *v1alpha1.AlertingRule {
	if id == "" {
		return nil
	}
	rule := v1alpha1.AlertingRule{
		Id:     id,
		Custom: custom,
		Level:  level,
	}
	if resRule != nil {
		rule.Name = resRule.Alert
		rule.Query = resRule.Expr.String()
		rule.Duration = resRule.For
		rule.Labels = resRule.Labels
		rule.Annotations = resRule.Annotations
		rule.State = stateInactiveString
		rule.Health = string(rules.HealthUnknown)
	}

	if cliRule != nil {
		if resRule == nil {
			// supple some necessary properties if the rule from the prometheusrule custom resources is nil.
			rule.Name = cliRule.Name
			rule.Duration = parseDurationSeconds(cliRule.Duration)
			rule.Labels = cliRule.Labels
			rule.Annotations = cliRule.Annotations
		}
		rule.Query = cliRule.Query

		// The state information and alerts associated with the rule are from the rule from the endpoint.
		if cliRule.Health != "" {
			rule.Health = cliRule.Health
		}
		rule.LastError = cliRule.LastError
		rule.LastEvaluation = cliRule.LastEvaluation
		rule.EvaluationDurationSeconds = cliRule.EvaluationTime

		rState := strings.ToLower(cliRule.State)
		cliRuleStateEmpty := rState == ""
		if !cliRuleStateEmpty {
			rule.State = rState
		}
		for _, a := range cliRule.Alerts {
			aState := strings.ToLower(a.State)
			if cliRuleStateEmpty {
				// for the rules gotten from prometheus or thanos ruler with a lower version, they may not contain
				// the state property, so compute the rule state by states of its alerts
				if alertState(rState) < alertState(aState) {
					rule.State = aState
				}
			}
			rule.Alerts = append(rule.Alerts, &v1alpha1.Alert{
				ActiveAt:    a.ActiveAt,
				Labels:      a.Labels,
				Annotations: a.Annotations,
				State:       aState,
				Value:       a.Value,

				RuleId:    rule.Id,
				RuleLevel: level,
			})
		}
	}
	return &rule
}

var (
	statePendingString  = rules.StatePending.String()
	stateFiringString   = rules.StateFiring.String()
	stateInactiveString = rules.StateInactive.String()
)

func alertState(state string) rules.AlertState {
	switch state {
	case statePendingString:
		return rules.StatePending
	case stateFiringString:
		return rules.StateFiring
	case stateInactiveString:
		return rules.StateInactive
	}
	return rules.StateInactive
}
