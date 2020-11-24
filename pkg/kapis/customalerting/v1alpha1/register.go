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
	"net/http"

	promresourcesclient "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ksapi "kubesphere.io/kubesphere/pkg/api"
	customalertingv1alpha1 "kubesphere.io/kubesphere/pkg/api/customalerting/v1alpha1"
	"kubesphere.io/kubesphere/pkg/apiserver/runtime"
	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/informers"
	"kubesphere.io/kubesphere/pkg/simple/client/customalerting"
)

const (
	groupName = "custom.alerting.kubesphere.io"
)

var GroupVersion = schema.GroupVersion{Group: groupName, Version: "v1alpha1"}

func AddToContainer(container *restful.Container, informers informers.InformerFactory,
	promResourceClient promresourcesclient.Interface, ruleClient customalerting.RuleClient,
	option *customalerting.Options) error {

	handler := newHandler(informers, promResourceClient, ruleClient, option)

	ws := runtime.NewWebService(GroupVersion)

	ws.Route(ws.GET("/rules").
		To(handler.handleListAlertingRules).
		Doc("list alerting rules with cluster level").
		Param(ws.QueryParameter("name", "rule name")).
		Param(ws.QueryParameter("state", "state of a rule based on its alerts, one of `firing`, `pending`, `inactive`")).
		Param(ws.QueryParameter("health", "health state of a rule based on the last execution, one of `ok`, `err`, `unknown`")).
		Param(ws.QueryParameter("label_filters", "label filters, concatenating multiple filters with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").DataFormat("key=%s,key~%s")).
		Param(ws.QueryParameter("sort_field", "sort field, one of `name`, `lastEvaluation`, `evaluationTime`")).
		Param(ws.QueryParameter("sort_type", "sort type, one of `asc`, `desc`")).
		Param(ws.QueryParameter("offset", "offset of the result set").DataType("integer").DefaultValue("0")).
		Param(ws.QueryParameter("limit", "limit size of the result set").DataType("integer").DefaultValue("10")).
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertingRuleList{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/namespaces/{namespace}/rules").
		To(handler.handleListAlertingRules).
		Doc("list alerting rules in specified namespace").
		Param(ws.QueryParameter("name", "rule name")).
		Param(ws.QueryParameter("state", "state of a rule based on its alerts, one of `firing`, `pending`, `inactive`")).
		Param(ws.QueryParameter("health", "health state of a rule based on the last execution, one of `ok`, `err`, `unknown`")).
		Param(ws.QueryParameter("label_filters", "label filters, concatenating multiple filters with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").DataFormat("key=%s,key~%s")).
		Param(ws.QueryParameter("sort_field", "sort field, one of `name`, `lastEvaluation`, `evaluationTime`")).
		Param(ws.QueryParameter("sort_type", "sort type, one of `asc`, `desc`")).
		Param(ws.QueryParameter("offset", "offset of the result set").DataType("integer").DefaultValue("0")).
		Param(ws.QueryParameter("limit", "limit size of the result set").DataType("integer").DefaultValue("10")).
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertingRuleList{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/rules/{ruleId}").
		To(handler.handleGetAlertingRules).
		Doc("get an alerting rule with specified id and cluster level").
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertingRule{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/namespaces/{namespace}/rules/{ruleId}").
		To(handler.handleGetAlertingRules).
		Doc("get an alerting rule with specified id in specified namespace").
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertingRule{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/alerts").
		To(handler.handleListAlerts).
		Doc("list alerts with cluster level").
		Param(ws.QueryParameter("state", "state, one of `firing`, `pending`, `inactive`")).
		Param(ws.QueryParameter("label_filters", "label filters, concatenating multiple filters with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").DataFormat("key=%s,key~%s")).
		Param(ws.QueryParameter("offset", "offset of the result set").DataType("integer").DefaultValue("0")).
		Param(ws.QueryParameter("limit", "limit size of the result set").DataType("integer").DefaultValue("10")).
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertList{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/namespaces/{namespace}/alerts").
		To(handler.handleListAlerts).
		Doc("list alerts in specified namespace.").
		Param(ws.QueryParameter("state", "state, one of `firing`, `pending`, `inactive`")).
		Param(ws.QueryParameter("label_filters", "label filters, concatenating multiple filters with commas, equal symbol for exact query, wave symbol for fuzzy query e.g. name~a").DataFormat("key=%s,key~%s")).
		Param(ws.QueryParameter("offset", "offset of the result set").DataType("integer").DefaultValue("0")).
		Param(ws.QueryParameter("limit", "limit size of the result set").DataType("integer").DefaultValue("10")).
		Returns(http.StatusOK, ksapi.StatusOK, customalertingv1alpha1.AlertList{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/rules/{ruleId}/alerts").
		To(handler.handleListAlertsWithRuleId).
		Doc("get alerts of rule with specified id and cluster level").
		Returns(http.StatusOK, ksapi.StatusOK, []customalertingv1alpha1.Alert{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.GET("/namespaces/{namespace}/rules/{ruleId}/alerts").
		To(handler.handleListAlertsWithRuleId).
		Doc("get alerts of rule with specified id in specified namespace").
		Returns(http.StatusOK, ksapi.StatusOK, []customalertingv1alpha1.Alert{}).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.PUT("/rules/{ruleId}").
		To(handler.handleUpdateAlertingRule).
		Doc("update an alerting rule with specified rule id and cluster level. return new id of the updated rule").
		Reads(customalertingv1alpha1.AlertingRule{}).
		Returns(http.StatusOK, ksapi.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.PUT("/namespaces/{namespace}/rules/{ruleId}").
		To(handler.handleUpdateAlertingRule).
		Doc("update an alerting rule with specified rule id into specified namespace. return new id of the updated rule").
		Reads(customalertingv1alpha1.AlertingRule{}).
		Returns(http.StatusOK, ksapi.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.POST("/rules").
		To(handler.handleCreateAlertingRule).
		Doc("create an alerting rule with cluster level. return id of the created rule").
		Reads(customalertingv1alpha1.AlertingRule{}).
		Returns(http.StatusOK, ksapi.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.POST("/namespaces/{namespace}/rules").
		To(handler.handleCreateAlertingRule).
		Doc("create an alerting rule into a specified namespace. return id of the created rule").
		Reads(customalertingv1alpha1.AlertingRule{}).
		Returns(http.StatusOK, ksapi.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.DELETE("/rules/{ruleId}").
		To(handler.handleDeleteAlertingRule).
		Doc("delete an alerting rule with specified rule id and cluster level").
		Returns(http.StatusOK, ksapi.StatusOK, nil).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	ws.Route(ws.DELETE("/namespaces/{namespace}/rules/{ruleId}").
		To(handler.handleDeleteAlertingRule).
		Doc("delete an alerting rule with specified rule id from specified namespace").
		Returns(http.StatusOK, ksapi.StatusOK, nil).
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.CustomAlertingTag}))

	container.Add(ws)

	return nil
}
