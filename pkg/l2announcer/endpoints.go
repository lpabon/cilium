// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2announcer

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

/*


	if svc.Spec.ExternalTrafficPolicy ==
		slim_corev1.ServiceExternalTrafficPolicy(lb.SVCTrafficPolicyLocal) {

		releaseLease := false

		// Get port number
		port := svc.Spec.HealthCheckNodePort
		if port <= 0 {
			l2a.params.Logger.Error("LUIS HealthCheckNodePort is zero")
			releaseLease = true
		}

		// Determine if we should be announcing for this service
		ok, err := l2a.checkHealthStatus(port)
		if err != nil {
			l2a.params.Logger.Error(fmt.Sprintf("LUIS unable to check health of service: %v", err))
			releaseLease = true
		}
		if !ok {
			l2a.params.Logger.Info("LUIS this host does --not-- have the locals")
			releaseLease = true
		}

		if releaseLease {
			return l2a.delSvc(key)
		}
		l2a.params.Logger.Info("LUIS this host --DOES-- have the locals")
	}

*/

// HealthCheckResponse defines the structure of the JSON response from the health check endpoint.
// Using a struct makes it easy and safe to parse the JSON.
type HealthCheckResponse struct {
	Service struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"service"`
	LocalEndpoints int `json:"localEndpoints"`
}

// CheckHealthStatus performs a health check against the provided URL.
// It returns true if the service is healthy (status 200 and localEndpoints > 0),
// otherwise it returns false and an error describing the issue.
func (l2a *L2Announcer) checkHealthStatus(port int32) (bool, error) {
	// LUIS
	// Perform the HTTP GET request.
	var (
		resp    *http.Response
		waitErr error
	)
	err := WaitFor(60*time.Second, 1*time.Second, func() (bool, error) {
		resp, waitErr = http.Get(fmt.Sprintf("http://localhost:%d", port))
		if waitErr != nil {
			l2a.params.Logger.Warn(fmt.Sprintf("failed to make HTTP request: %w", waitErr))
			return true, nil
		}

		return false, nil
	})
	if err != nil {
		return false, waitErr
	}

	// Ensure the response body is closed when the function returns.
	defer resp.Body.Close()

	// First, check if the HTTP status code is 200 OK.
	// The user's example shows 503, so we handle non-200 cases.
	if resp.StatusCode != http.StatusOK {
		// Read the body to include it in the error message for more context.
		return false, fmt.Errorf("health check failed with status code %d", resp.StatusCode)
	}

	// The status is 200, so now we parse the JSON body.
	var healthData HealthCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthData); err != nil {
		return false, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	// Finally, check if the number of local endpoints is greater than 0.
	if healthData.LocalEndpoints > 0 {
		l2a.params.Logger.Info(fmt.Sprintf(
			"Health check successful for service %s/%s. Local Endpoints: %d\n",
			healthData.Service.Namespace,
			healthData.Service.Name,
			healthData.LocalEndpoints,
		))
		return true, nil
	}

	// If we reach here, it means localEndpoints was 0 or less.
	return false, fmt.Errorf("service is unhealthy: localEndpoints is %d", healthData.LocalEndpoints)
}

// Implementation of endpointmanager.Subscriber interface

// EndpointCreated is called when a new endpoint is created
func (l2a *L2Announcer) EndpointCreated(ep *endpoint.Endpoint) {
	// Create leader
	l2a.checkEndpointCount()

	for _, svc := range l2a.svcStore.List() {
		// Check if the service has local endpoints
		if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal {
			if l2a.HasLocalEndpoint(svc) {
				// Create leader
				l2a.addSelectedService(svc, nil)
			}
		}
	}
}

// EndpointDeleted is called when an endpoint is deleted
func (l2a *L2Announcer) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	// delete leader
	l2a.checkEndpointCount()
}

// EndpointRestored is called when an endpoint is restored
func (l2a *L2Announcer) EndpointRestored(ep *endpoint.Endpoint) {
	// Handle restored endpoints similar to created ones
	l2a.EndpointCreated(ep)
}

// HasLocalEndpoint checks if a service has at least one local endpoint
func (l2a *L2Announcer) HasLocalEndpoint(svc *slim_corev1.Service) bool {

	svcName := lb.NewServiceName(svc.Namespace, svc.Name)
	count, exists := l2a.localEndpoints[svcName]
	l2a.params.Logger.Info("LUIS HasLocalEndpoint",
		"service", svcName.String(),
		"exists", exists,
		"endpointCount", count)

	if svc.Spec.ExternalTrafficPolicy ==
		slim_corev1.ServiceExternalTrafficPolicy(lb.SVCTrafficPolicyLocal) {

		// Get port number
		port := svc.Spec.HealthCheckNodePort
		if port <= 0 {
			l2a.params.Logger.Error("LUIS HealthCheckNodePort is zero",
				"service", svcName.String())
		}

		// Determine if we should be announcing for this service
		ok, err := l2a.checkHealthStatus(port)
		if err != nil {
			l2a.params.Logger.Error(fmt.Sprintf("LUIS unable to check health of service: %v", err),
				"service", svcName.String())
			return false
		}
		if !ok {
			l2a.params.Logger.Info("LUIS this host does --not-- have the locals",
				"service", svcName.String())
			return false
		}

		l2a.params.Logger.Info("LUIS this host --DOES-- have the locals",
			"service", svcName.String())
		return true
	}

	return false
}

// checkEndpointCount verifies if there are any local endpoints for a service
func (l2a *L2Announcer) checkEndpointCount() error {
	// Get selected services for this service name
	for _, ss := range l2a.selectedServices {
		if ss.externalTrafficPolicyLocal {
			// For services with externalTrafficPolicy=Local, if we're not the leader
			// we need to verify if we have endpoints to potentially start leading
			hasLocalEndpoints := l2a.HasLocalEndpoint(ss.svc)
			svcName := ss.svc.Name

			// Log the current state for observability
			l2a.params.Logger.Info("LUIS Checking local endpoints",
				"service", svcName,
				"hasLocalEndpoints", hasLocalEndpoints)

			if ss.currentlyLeader && !hasLocalEndpoints {
				// No local endpoints, must release leadership
				l2a.params.Logger.Info("LUIS Leader lost all local endpoints, releasing leadership",
					"service", svcName)
				return l2a.delSvc(serviceKey(ss.svc))
			}
		}
	}
	return nil
}
