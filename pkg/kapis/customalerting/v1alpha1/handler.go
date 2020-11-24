/*
Copyright 2020 KubeSphere Authors

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

package v1alpha1

import (
	promresourcesclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/emicklei/go-restful"
	"k8s.io/klog"
	ksapi "kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
	"kubesphere.io/kubesphere/pkg/informers"
	customalertingmodels "kubesphere.io/kubesphere/pkg/models/customalerting"
	"kubesphere.io/kubesphere/pkg/simple/client/customalerting"
)

type handler struct {
	operator customalertingmodels.Operator
}

func newHandler(informers informers.InformerFactory,
	promResourceClient promresourcesclient.Interface, ruleClient customalerting.RuleClient,
	option *customalerting.Options) *handler {
	return &handler{
		operator: customalertingmodels.NewOperator(
			informers, promResourceClient, ruleClient, option),
	}
}

func (h *handler) handleListAlertingRules(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	query, err := v1alpha1.ParseAlertingRuleQueryParameter(req)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	rules, err := h.operator.ListAlertingRules(req.Request.Context(), ruleNamespace, query)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(rules)
}

func (h *handler) handleGetAlertingRules(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	ruleId := req.PathParameter("ruleId")
	rule, err := h.operator.GetAlertingRule(req.Request.Context(), ruleNamespace, ruleId)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(rule)
}

func (h *handler) handleListAlerts(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	query, err := v1alpha1.ParseAlertQueryParameter(req)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	alerts, err := h.operator.ListAlerts(req.Request.Context(), ruleNamespace, query)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(alerts)
}

func (h *handler) handleListAlertsWithRuleId(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	ruleId := req.PathParameter("ruleId")
	alerts, err := h.operator.ListAlertsWithRuleId(req.Request.Context(), ruleNamespace, ruleId)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(alerts)
}

func (h *handler) handleCreateAlertingRule(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")

	var rule v1alpha1.AlertingRule
	if err := req.ReadEntity(&rule); err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	if err := rule.Validate(); err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}

	id, err := h.operator.CreateAlertingRule(ruleNamespace, &rule)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(id)
}

func (h *handler) handleUpdateAlertingRule(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	ruleId := req.PathParameter("ruleId")

	var rule v1alpha1.AlertingRule
	if err := req.ReadEntity(&rule); err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	if err := rule.Validate(); err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}

	rule.Id = ruleId

	newId, err := h.operator.UpdateAlertingRule(ruleNamespace, &rule)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(newId)
}

func (h *handler) handleDeleteAlertingRule(req *restful.Request, resp *restful.Response) {
	ruleNamespace := req.PathParameter("namespace")
	ruleId := req.PathParameter("ruleId")

	err := h.operator.DeleteAlertingRule(ruleNamespace, ruleId)
	if err != nil {
		klog.Error(err)
		ksapi.HandleBadRequest(resp, nil, err)
		return
	}
	resp.WriteEntity(nil)
}
