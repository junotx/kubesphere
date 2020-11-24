package customalerting

import (
	"context"
	"strings"

	promresourcesv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	prominformersv1 "github.com/coreos/prometheus-operator/pkg/client/informers/externalversions/monitoring/v1"
	promresourcesclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformersv1 "k8s.io/client-go/informers/core/v1"
	"kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/informers"
	"kubesphere.io/kubesphere/pkg/models/customalerting/rules"
	"kubesphere.io/kubesphere/pkg/simple/client/customalerting"
)

const (
	rulerNamespace                 = constants.KubeSphereMonitoringNamespace
	customAlertingRuleGroupDefault = "alerting.custom.defaults"

	errThanosRulerNotEnabled = "operation to custom alerting rule can not be done because thanos ruler is not enabled"
)

var (
	maxSecretSize        = corev1.MaxSecretSize
	maxConfigMapDataSize = int(float64(maxSecretSize) * 0.45)
)

// Operator contains all operations to alerting rules. The operations will involve manipulations of prometheusrule
// custom resources where the rules are persisted, and querying the rules state from prometheus endpoint and thanos
// ruler endpoint.
// For the following apis against prometheus and thanos ruler, if namespace is empty, do operations to alerting rules
// with cluster level, or do operations only to rules of the specified namespaces.
// The rules selected by prometheus are considered to built-in and non-custom rules which can only be modified.
// All custom rules will be configured for thanos ruler, so the operations to custom alerting rule can not be done
// if thanos ruler is not enabled.
type Operator interface {
	GetAlertingRule(ctx context.Context, namespace, ruleId string) (*v1alpha1.AlertingRule, error)
	ListAlertingRules(ctx context.Context, namespace string, query *v1alpha1.AlertingRuleQuery) (*v1alpha1.AlertingRuleList, error)

	CreateAlertingRule(namespace string, rule *v1alpha1.AlertingRule) (string, error)
	UpdateAlertingRule(namespace string, rule *v1alpha1.AlertingRule) (string, error)
	DeleteAlertingRule(namespace, ruleId string) error

	ListAlerts(ctx context.Context, namespace string, query *v1alpha1.AlertQuery) (*v1alpha1.AlertList, error)
	ListAlertsWithRuleId(ctx context.Context, namespace string, ruleId string) ([]*v1alpha1.Alert, error)
}

func NewOperator(informers informers.InformerFactory,
	promResourceClient promresourcesclient.Interface, ruleClient customalerting.RuleClient,
	option *customalerting.Options) Operator {
	o := operator{
		namespaceInformer: informers.KubernetesSharedInformerFactory().Core().V1().Namespaces(),

		prometheusResourceClient: promResourceClient,

		prometheusInformer:     informers.PrometheusSharedInformerFactory().Monitoring().V1().Prometheuses(),
		thanosRulerInformer:    informers.PrometheusSharedInformerFactory().Monitoring().V1().ThanosRulers(),
		prometheusRuleInformer: informers.PrometheusSharedInformerFactory().Monitoring().V1().PrometheusRules(),

		ruleClient: ruleClient,

		thanosRuleResourceLabels: make(map[string]string),
	}

	if option != nil && len(option.ThanosRuleResourceLabels) != 0 {
		lblStrings := strings.Split(option.ThanosRuleResourceLabels, ",")
		for _, lblString := range lblStrings {
			lbl := strings.Split(lblString, "=")
			if len(lbl) == 2 {
				o.thanosRuleResourceLabels[lbl[0]] = lbl[1]
			}
		}
	}

	return &o
}

type operator struct {
	ruleClient customalerting.RuleClient

	prometheusResourceClient promresourcesclient.Interface

	prometheusInformer     prominformersv1.PrometheusInformer
	thanosRulerInformer    prominformersv1.ThanosRulerInformer
	prometheusRuleInformer prominformersv1.PrometheusRuleInformer

	namespaceInformer coreinformersv1.NamespaceInformer

	thanosRuleResourceLabels map[string]string
}

func (o *operator) CreateAlertingRule(namespace string, rule *v1alpha1.AlertingRule) (string, error) {
	var (
		ruleNamespace *corev1.Namespace
		level         v1alpha1.RuleLevel
		id            string
		err           error
	)

	if namespace == "" {
		level = v1alpha1.RuleLevelCluster
		ruleNamespace, err = o.namespaceInformer.Lister().Get(rulerNamespace)
		if err != nil {
			return "", err
		}

		if id, err = rules.GenApiRuleId(customAlertingRuleGroupDefault, rule); err != nil {
			return "", errors.Wrap(err, rules.ErrGenRuleId)
		}
		ruler, err := o.getPrometheusRuler()
		if err != nil {
			return "", err
		}
		if ruler != nil {
			_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
			if err != nil {
				return "", err
			}
			if resRule != nil {
				return "", errors.Errorf("a rule with same config already exists")
			}
		}
	} else {
		level = v1alpha1.RuleLevelNamespace
		ruleNamespace, err = o.namespaceInformer.Lister().Get(namespace)
		if err != nil {
			return "", err
		}

		expr, err := rules.InjectExprNamespaceLabel(rule.Query, ruleNamespace.Name)
		if err != nil {
			return "", err
		}
		rule.Query = expr
		if id, err = rules.GenApiRuleId(customAlertingRuleGroupDefault, rule); err != nil {
			return "", errors.Wrap(err, rules.ErrGenRuleId)
		}
	}

	ruler, err := o.getThanosRuler()
	if err != nil {
		return "", err
	}
	if ruler == nil {
		return "", errors.New(errThanosRulerNotEnabled)
	}
	_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
	if err != nil {
		return "", err
	}
	if resRule != nil {
		return "", errors.Errorf("a rule with same config already exists")
	}
	if err = ruler.AddAlertingRule(ruleNamespace, rule, customAlertingRuleGroupDefault, level); err != nil {
		return "", errors.Wrap(err, "error adding an alerting rule: ")
	} else {
		return id, nil
	}
}

func (o *operator) UpdateAlertingRule(namespace string, rule *v1alpha1.AlertingRule) (string, error) {
	if rule.Id == "" {
		return "", errors.Errorf("rule id can not be empty when updating a rule")
	}

	var (
		ruleNamespace *corev1.Namespace
		level         v1alpha1.RuleLevel
		id            = rule.Id
		err           error
	)

	if namespace == "" {
		level = v1alpha1.RuleLevelCluster
		ruleNamespace, err = o.namespaceInformer.Lister().Get(rulerNamespace)
		if err != nil {
			return "", err
		}

		ruler, err := o.getPrometheusRuler()
		if err != nil {
			return "", err
		}
		if ruler != nil {
			_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
			if err != nil {
				return "", err
			}
			if resRule != nil {
				return "", errors.Errorf("can not update a non-custom rule")
			}
		}
	} else {
		level = v1alpha1.RuleLevelNamespace
		ruleNamespace, err = o.namespaceInformer.Lister().Get(namespace)
		if err != nil {
			return "", err
		}

		expr, err := rules.InjectExprNamespaceLabel(rule.Query, ruleNamespace.Name)
		if err != nil {
			return "", err
		}
		rule.Query = expr
	}

	ruler, err := o.getThanosRuler()
	if err != nil {
		return "", err
	}
	if ruler == nil {
		return "", errors.New(errThanosRulerNotEnabled)
	}
	_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
	if err != nil {
		return "", err
	}
	if resRule == nil {
		return "", errors.Errorf("can not find a rule with rule id %s", id)
	}

	if nid, err := ruler.UpdateAlertingRule(ruleNamespace, id, rule, level); err != nil {
		return "", errors.Wrap(err, "error updating an alerting rule")
	} else {
		return nid, nil
	}
}

func (o *operator) DeleteAlertingRule(namespace, id string) error {
	var (
		ruleNamespace *corev1.Namespace
		level         v1alpha1.RuleLevel
		err           error
	)

	if namespace == "" {
		level = v1alpha1.RuleLevelCluster
		ruleNamespace, err = o.namespaceInformer.Lister().Get(rulerNamespace)
		if err != nil {
			return err
		}

		ruler, err := o.getPrometheusRuler()
		if err != nil {
			return err
		}
		if ruler != nil {
			_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
			if err != nil {
				return err
			}
			if resRule != nil {
				return errors.Errorf("can not delete a non-custom rule")
			}
		}
	} else {
		level = v1alpha1.RuleLevelNamespace
		ruleNamespace, err = o.namespaceInformer.Lister().Get(namespace)
		if err != nil {
			return err
		}
	}

	ruler, err := o.getThanosRuler()
	if err != nil {
		return err
	}
	if ruler == nil {
		return errors.New(errThanosRulerNotEnabled)
	}
	if _, err := ruler.DeleteAlertingRule(ruleNamespace, id, level); err != nil {
		return errors.Wrap(err, "error deleting an alerting rule")
	}

	return nil
}

func (o *operator) GetAlertingRule(ctx context.Context, namespace, id string) (*v1alpha1.AlertingRule, error) {
	var (
		ruleNamespace *corev1.Namespace
		level         v1alpha1.RuleLevel
		err           error
	)

	if namespace == "" {
		level = v1alpha1.RuleLevelCluster
		ruleNamespace, err = o.namespaceInformer.Lister().Get(rulerNamespace)
		if err != nil {
			return nil, err
		}

		ruler, err := o.getPrometheusRuler()
		if err != nil {
			return nil, err
		}
		if ruler == nil {
			cliRuleGroups, err := o.ruleClient.PrometheusRules(ctx)
			if err != nil {
				return nil, err
			}
			cliRule, err := rules.FindCliRule(cliRuleGroups, id, nil)
			if err != nil {
				return nil, err
			}
			if cliRule != nil {
				return rules.MixAlertingRule(id, nil, cliRule, false, level), nil
			}
		} else {
			_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
			if err != nil {
				return nil, err
			}
			if resRule != nil {
				cliRuleGroups, err := o.ruleClient.PrometheusRules(ctx)
				if err != nil {
					return nil, err
				}
				cliRule, err := rules.FindCliRule(cliRuleGroups, id, ruler.ExternalLabels())
				if err != nil {
					return nil, err
				}
				return rules.MixAlertingRule(id, resRule, cliRule, false, level), nil
			}
		}
	} else {
		level = v1alpha1.RuleLevelNamespace
		ruleNamespace, err = o.namespaceInformer.Lister().Get(namespace)
		if err != nil {
			return nil, err
		}
	}

	ruler, err := o.getThanosRuler()
	if err != nil {
		return nil, err
	}
	if ruler == nil {
		return nil, errors.Errorf("can not find a rule with rule id %s", id)
	}

	_, _, resRule, err := ruler.GetAlertingRule(ruleNamespace, id, level)
	if err != nil {
		return nil, err
	}
	if resRule == nil {
		return nil, errors.Errorf("can not find a rule with rule id %s", id)
	}
	cliRuleGroups, err := o.ruleClient.ThanosRules(ctx)
	if err != nil {
		return nil, err
	}
	cliRule, err := rules.FindCliRule(cliRuleGroups, id, ruler.ExternalLabels())
	if err != nil {
		return nil, err
	}
	return rules.MixAlertingRule(id, resRule, cliRule, true, level), nil
}

func (o *operator) ListAlertingRules(ctx context.Context, namespace string, query *v1alpha1.AlertingRuleQuery) (
	*v1alpha1.AlertingRuleList, error) {
	alertingRules, err := o.listAlertingRules(ctx, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	alertingRules = query.Filter(alertingRules)
	query.Sort(alertingRules)

	return &v1alpha1.AlertingRuleList{
		Total: len(alertingRules),
		Items: query.Sub(alertingRules),
	}, nil
}

func (o *operator) listAlertingRules(ctx context.Context, namespace string) ([]*v1alpha1.AlertingRule, error) {
	var (
		ruleNamespace *corev1.Namespace
		level         v1alpha1.RuleLevel
		err           error

		// rules from prometheusrule resources
		promRuleResources, thanosRuleResources []*promresourcesv1.PrometheusRule
		// rules from prometheus or thanos ruler endpoints
		promCliRuleGroups, thanosCliRuleGroups []*customalerting.RuleGroup
		// rules from endpoints may contain some external labels and will be removed when generating rule id.
		promRulerExtLabels, thanosRulerExtLabels func() map[string]string
		// indicates the presence of prometheus custom resource or thanosruler custom resource.
		hasPromRuler, hasThanosRuler bool
	)

	if namespace == "" {
		level = v1alpha1.RuleLevelCluster
		ruleNamespace, err = o.namespaceInformer.Lister().Get(rulerNamespace)
		if err != nil {
			return nil, err
		}

		ruler, err := o.getPrometheusRuler()
		if err != nil {
			return nil, err
		}
		promCliRuleGroups, err = o.ruleClient.PrometheusRules(ctx)
		if err != nil {
			return nil, err
		}
		if ruler != nil {
			hasPromRuler = true
			promRulerExtLabels = ruler.ExternalLabels()
			promRuleResources, err = ruler.ListRuleResources(ruleNamespace, level)
			if err != nil {
				return nil, err
			}
		}
	} else {
		level = v1alpha1.RuleLevelNamespace
		ruleNamespace, err = o.namespaceInformer.Lister().Get(namespace)
		if err != nil {
			return nil, err
		}
	}

	ruler, err := o.getThanosRuler()
	if err != nil {
		return nil, err
	}
	if ruler != nil {
		hasThanosRuler = true
		thanosRulerExtLabels = ruler.ExternalLabels()
		thanosRuleResources, err = ruler.ListRuleResources(ruleNamespace, level)
		if err != nil {
			return nil, err
		}
		thanosCliRuleGroups, err = o.ruleClient.ThanosRules(ctx)
		if err != nil {
			return nil, err
		}
	}

	return rules.MixAlertingRules(
		ruleNamespace.Name,
		promRuleResources,
		thanosRuleResources,
		promCliRuleGroups,
		thanosCliRuleGroups,
		level,
		hasPromRuler,
		hasThanosRuler,
		promRulerExtLabels,
		thanosRulerExtLabels)
}

func (o *operator) ListAlerts(ctx context.Context, namespace string, query *v1alpha1.AlertQuery) (*v1alpha1.AlertList, error) {
	alertingRules, err := o.listAlertingRules(ctx, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	var alerts []*v1alpha1.Alert
	for _, rule := range alertingRules {
		alerts = append(alerts, query.Filter(rule.Alerts)...)
	}
	query.Sort(alerts)

	return &v1alpha1.AlertList{
		Total: len(alerts),
		Items: query.Sub(alerts),
	}, nil
}

func (o *operator) ListAlertsWithRuleId(ctx context.Context, namespace string, ruleId string) ([]*v1alpha1.Alert, error) {
	rule, err := o.GetAlertingRule(ctx, namespace, ruleId)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	if rule != nil {
		alerts := rule.Alerts
		var alertQuery v1alpha1.AlertQuery
		alertQuery.Sort(alerts) // Just call its sort method
		return alerts, nil
	}
	return nil, nil
}

// getPrometheusRuler gets the cluster-in prometheus
func (o *operator) getPrometheusRuler() (*rules.PrometheusRuler, error) {
	prometheuses, err := o.prometheusInformer.Lister().Prometheuses(rulerNamespace).List(labels.Everything())
	if err != nil {
		return nil, errors.Wrap(err, "error listing prometheuses: ")
	}
	if len(prometheuses) > 1 {
		// it is not supported temporarily to have multiple prometheuses in the monitoring namespace
		return nil, errors.Errorf(
			"there is more than one prometheus custom resource in %s", rulerNamespace)
	}
	if len(prometheuses) == 0 {
		return nil, nil
	}

	return rules.NewPrometheusRuler(prometheuses[0], o.prometheusRuleInformer, o.prometheusResourceClient), nil
}

func (o *operator) getThanosRuler() (*rules.ThanosRuler, error) {
	thanosrulers, err := o.thanosRulerInformer.Lister().ThanosRulers(rulerNamespace).List(labels.Everything())
	if err != nil {
		return nil, errors.Wrap(err, "error listing thanosrulers: ")
	}
	if len(thanosrulers) > 1 {
		// it is not supported temporarily to have multiple thanosrulers in the monitoring namespace
		return nil, errors.Errorf(
			"there is more than one thanosruler custom resource in %s", rulerNamespace)
	}
	if len(thanosrulers) == 0 {
		// if there is no thanos ruler, custom rules will not be supported
		return nil, nil
	}

	return rules.NewThanosRuler(thanosrulers[0], o.prometheusRuleInformer,
		o.prometheusResourceClient, o.thanosRuleResourceLabels), nil
}
