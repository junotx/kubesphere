package rules

import (
	promresourcesv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	prominformersv1 "github.com/coreos/prometheus-operator/pkg/client/informers/externalversions/monitoring/v1"
	promresourcesclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
)

const (
	ruleResourceLabelKeyLevel        = "custom-alerting-rule-level"
	customAlertingRuleResourcePrefix = "custom-alerting-rule-"

	errConvertLabelSelector = "error converting label selector"
)

var (
	maxSecretSize        = corev1.MaxSecretSize
	maxConfigMapDataSize = int(float64(maxSecretSize) * 0.45)
)

type ruleResource promresourcesv1.PrometheusRule

func (r *ruleResource) deleteAlertingRule(id string) (bool, error) {
	ok, _, err := r.updateAlertingRule(id, nil)
	return ok, err
}

func (r *ruleResource) updateAlertingRule(id string, newRule *v1alpha1.AlertingRule) (bool, string, error) {
	var (
		newGroups []promresourcesv1.RuleGroup
		ok        bool
		newId     string
	)

	for _, group := range r.Spec.Groups {
		newGroup := group.DeepCopy()
		newGroup.Rules = nil
		for _, rule := range group.Rules {
			if rule.Alert != "" {
				rid, e := GenResRuleId(group.Name, &rule)
				if e != nil {
					return false, "", errors.Wrap(e, ErrGenRuleId)
				}
				if rid == id {
					if ok { // delete if there have been already a deletion or update operation
						continue
					}
					if newRule == nil { // delete
						ok = true
						continue
					}
					// update
					rule.Alert = newRule.Name
					rule.Expr = intstr.FromString(newRule.Query)
					rule.For = newRule.Duration
					rule.Labels = newRule.Labels
					rule.Annotations = newRule.Annotations
					newId, e = GenResRuleId(group.Name, &rule)
					if e != nil {
						return false, "", errors.Wrap(e, ErrGenRuleId)
					}
					ok = true
				}
			}
			newGroup.Rules = append(newGroup.Rules, rule)
		}
		if len(newGroup.Rules) > 0 {
			newGroups = append(newGroups, *newGroup)
		}
	}

	if ok {
		r.Spec.Groups = newGroups
	}
	return ok, newId, nil
}

func (r *ruleResource) addAlertingRule(groupName string, rule *promresourcesv1.Rule) (bool, error) {
	var (
		err   error
		pr    = (promresourcesv1.PrometheusRule)(*r)
		newPr = pr.DeepCopy()
		ok    bool
	)

	for i := 0; i < len(newPr.Spec.Groups); i++ {
		if newPr.Spec.Groups[i].Name == groupName {
			newPr.Spec.Groups[i].Rules = append(newPr.Spec.Groups[i].Rules, *rule)
			ok = true
			break
		}
	}
	if !ok { // add group when there is no group with the specified groupName
		newPr.Spec.Groups = append(newPr.Spec.Groups, promresourcesv1.RuleGroup{
			Name:  groupName,
			Rules: []promresourcesv1.Rule{*rule},
		})
	}

	content, err := yaml.Marshal(newPr)
	if err != nil {
		return false, errors.Wrap(err, "failed to unmarshal content")
	}

	if len(string(content)) < maxConfigMapDataSize { // check size limit
		r.Spec.Groups = newPr.Spec.Groups
		return true, nil
	}

	return false, nil
}

func (r *ruleResource) commit(prometheusResourceClient promresourcesclient.Interface) error {
	var pr = (promresourcesv1.PrometheusRule)(*r)
	if len(pr.Spec.Groups) == 0 {
		return prometheusResourceClient.MonitoringV1().PrometheusRules(r.Namespace).Delete(r.Name, &metav1.DeleteOptions{})
	}
	newPr, err := prometheusResourceClient.MonitoringV1().PrometheusRules(r.Namespace).Update(&pr)
	if err != nil {
		return err
	}
	newPr.DeepCopyInto(&pr)
	return nil
}

type PrometheusRuler struct {
	resource *promresourcesv1.Prometheus
	informer prominformersv1.PrometheusRuleInformer
	client   promresourcesclient.Interface
}

func NewPrometheusRuler(resource *promresourcesv1.Prometheus, informer prominformersv1.PrometheusRuleInformer,
	client promresourcesclient.Interface) *PrometheusRuler {
	return &PrometheusRuler{
		resource: resource,
		informer: informer,
		client:   client,
	}
}

func findAlertingRule(prs []*promresourcesv1.PrometheusRule, id string) (
	*promresourcesv1.PrometheusRule, *promresourcesv1.RuleGroup, *promresourcesv1.Rule, error) {
	for _, pr := range prs {
		for i := 0; i < len(pr.Spec.Groups); i++ {
			g := pr.Spec.Groups[i]
			for j := 0; j < len(g.Rules); j++ {
				r := g.Rules[j]
				if r.Alert == "" {
					continue
				}
				rid, e := GenResRuleId(g.Name, &r)
				if e != nil {
					return nil, nil, nil, errors.Wrap(e, ErrGenRuleId)
				}
				if rid == id {
					return pr, &g, &r, nil
				}
			}
		}
	}
	return nil, nil, nil, nil
}

func (r *PrometheusRuler) GetAlertingRule(ruleNamespace *corev1.Namespace, id string, level v1alpha1.RuleLevel) (
	*promresourcesv1.PrometheusRule, *promresourcesv1.RuleGroup, *promresourcesv1.Rule, error) {
	prometheusRules, err := r.ListRuleResources(ruleNamespace, level)
	if err != nil {
		return nil, nil, nil, err
	}
	return findAlertingRule(prometheusRules, id)
}

func (r *PrometheusRuler) ListRuleResources(ruleNamespace *corev1.Namespace,
	level v1alpha1.RuleLevel) ([]*promresourcesv1.PrometheusRule, error) {

	// refer to the comment of Prometheus.Spec.RuleNamespaceSelector
	if r.resource.Spec.RuleNamespaceSelector == nil {
		if r.resource.Namespace != ruleNamespace.Name {
			return nil, nil
		}
	} else {
		rnSelector, err := metav1.LabelSelectorAsSelector(r.resource.Spec.RuleNamespaceSelector)
		if err != nil {
			return nil, errors.Wrap(err, errConvertLabelSelector)
		}

		if !rnSelector.Matches(labels.Set(ruleNamespace.Labels)) {
			return nil, nil
		}
	}

	rSelector, err := metav1.LabelSelectorAsSelector(r.resource.Spec.RuleSelector)
	if err != nil {
		return nil, errors.Wrap(err, errConvertLabelSelector)
	}

	return r.informer.Lister().PrometheusRules(ruleNamespace.Name).List(rSelector)
}

func (r *PrometheusRuler) ExternalLabels() func() map[string]string {
	// ignoring the external labels because rules gotten from prometheus endpoint do not include them
	return nil
}

type ThanosRuler struct {
	resource           *promresourcesv1.ThanosRuler
	informer           prominformersv1.PrometheusRuleInformer
	client             promresourcesclient.Interface
	ruleResourceLabels map[string]string
}

func NewThanosRuler(resource *promresourcesv1.ThanosRuler, informer prominformersv1.PrometheusRuleInformer,
	client promresourcesclient.Interface, ruleResourceLabels map[string]string) *ThanosRuler {
	return &ThanosRuler{
		resource:           resource,
		informer:           informer,
		client:             client,
		ruleResourceLabels: ruleResourceLabels,
	}
}

func (r *ThanosRuler) GetAlertingRule(ruleNamespace *corev1.Namespace, id string, level v1alpha1.RuleLevel) (
	*promresourcesv1.PrometheusRule, *promresourcesv1.RuleGroup, *promresourcesv1.Rule, error) {
	prometheusRules, err := r.ListRuleResources(ruleNamespace, level)
	if err != nil {
		return nil, nil, nil, err
	}
	return findAlertingRule(prometheusRules, id)
}

func (r *ThanosRuler) ListRuleResources(ruleNamespace *corev1.Namespace,
	level v1alpha1.RuleLevel) ([]*promresourcesv1.PrometheusRule, error) {

	// refer to the comment of Prometheus.Spec.RuleNamespaceSelector
	if r.resource.Spec.RuleNamespaceSelector == nil {
		if r.resource.Namespace != ruleNamespace.Name {
			return nil, nil
		}
	} else {
		rnSelector, err := metav1.LabelSelectorAsSelector(r.resource.Spec.RuleNamespaceSelector)
		if err != nil {
			return nil, errors.Wrap(err, errConvertLabelSelector)
		}

		if !rnSelector.Matches(labels.Set(ruleNamespace.Labels)) {
			return nil, nil
		}
	}

	rSelector, err := metav1.LabelSelectorAsSelector(r.resource.Spec.RuleSelector)
	if err != nil {
		return nil, errors.Wrap(err, errConvertLabelSelector)
	}
	if requirements, ok := labels.Set(map[string]string{
		ruleResourceLabelKeyLevel: string(level),
	}).AsSelector().Requirements(); ok {
		rSelector = rSelector.Add(requirements...)
	}

	return r.informer.Lister().PrometheusRules(ruleNamespace.Name).List(rSelector)
}

func (r *ThanosRuler) AddAlertingRule(ruleNamespace *corev1.Namespace, rule *v1alpha1.AlertingRule,
	group string, level v1alpha1.RuleLevel) error {
	prometheusRules, err := r.ListRuleResources(ruleNamespace, level)
	if err != nil {
		return err
	}

	var addedRule = promresourcesv1.Rule{
		Alert:       rule.Name,
		Expr:        intstr.FromString(rule.Query),
		For:         rule.Duration,
		Labels:      rule.Labels,
		Annotations: rule.Annotations,
	}
	for _, prometheusRule := range prometheusRules {
		resource := ruleResource(*prometheusRule)
		if ok, err := resource.addAlertingRule(group, &addedRule); err != nil {
			return err
		} else if ok {
			if err = resource.commit(r.client); err != nil {
				return err
			}
			return nil
		}
	}
	// create a new prometheus rule resource and add rule into it,
	// because those existing prometheus rule resources are full.
	var lbls = make(map[string]string)
	for k, v := range r.ruleResourceLabels {
		lbls[k] = v
	}
	lbls[ruleResourceLabelKeyLevel] = string(level)
	newPromRule := promresourcesv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    ruleNamespace.Name,
			GenerateName: customAlertingRuleResourcePrefix,
			Labels:       lbls,
		},
		Spec: promresourcesv1.PrometheusRuleSpec{
			Groups: []promresourcesv1.RuleGroup{{
				Name:  group,
				Rules: []promresourcesv1.Rule{addedRule},
			}},
		},
	}
	if _, err := r.client.MonitoringV1().
		PrometheusRules(ruleNamespace.Name).Create(&newPromRule); err != nil {
		return errors.Wrapf(err, "error creating a prometheus rule resource %s/%s",
			newPromRule.Namespace, newPromRule.Name)
	}

	return nil
}

func (r *ThanosRuler) DeleteAlertingRule(ruleNamespace *corev1.Namespace, id string,
	level v1alpha1.RuleLevel) (bool, error) {
	prometheusRules, err := r.ListRuleResources(ruleNamespace, level)
	if err != nil {
		return false, err
	}
	var ook bool
	for _, prometheusRule := range prometheusRules {
		resource := ruleResource(*prometheusRule)
		if ok, err := resource.deleteAlertingRule(id); err != nil {
			return false, err
		} else if ok {
			if err = resource.commit(r.client); err != nil {
				return false, err
			}
			ook = true
		}
	}

	return ook, nil
}

func (r *ThanosRuler) UpdateAlertingRule(ruleNamespace *corev1.Namespace, id string,
	newRule *v1alpha1.AlertingRule, level v1alpha1.RuleLevel) (string, error) {

	prometheusRules, err := r.ListRuleResources(ruleNamespace, level)
	if err != nil {
		return "", err
	}

	var success bool
	var newId string
	for _, prometheusRule := range prometheusRules {
		resource := ruleResource(*prometheusRule)
		if success { // If the update has been successful, delete the possible same rule in other resources
			if ok, err := resource.deleteAlertingRule(id); err != nil {
				return "", err
			} else if ok {
				if err = resource.commit(r.client); err != nil {
					return "", err
				}
			}
			continue
		}
		if ok, nid, err := resource.updateAlertingRule(id, newRule); err != nil {
			return "", err
		} else if ok {
			if err = resource.commit(r.client); err != nil {
				return "", err
			}
			success = true
			newId = nid
		}
	}
	if success {
		return newId, nil
	}
	return "", errors.Errorf("can not find rule with id(%s) in namespace(%s)", id, ruleNamespace.Name)
}

func (r *ThanosRuler) ExternalLabels() func() map[string]string {
	// rules gotten from thanos ruler endpoint include the labels
	lbls := make(map[string]string)
	for k, v := range r.resource.Spec.Labels {
		lbls[k] = v
	}
	return func() map[string]string {
		return lbls
	}
}
