package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TwiN/gatus/v5/alerting"
	"github.com/TwiN/gatus/v5/alerting/alert"
	"github.com/TwiN/gatus/v5/alerting/provider/discord"
	"github.com/TwiN/gatus/v5/config"
	"github.com/TwiN/gatus/v5/config/endpoint"
	"github.com/TwiN/gatus/v5/config/maintenance"
	"github.com/TwiN/gatus/v5/storage/store"
	"github.com/TwiN/gatus/v5/storage/store/common/paging"
)

func TestCreateExternalEndpointResult(t *testing.T) {
	defer store.Get().Clear()
	defer cache.Clear()
	cfg := &config.Config{
		Alerting: &alerting.Config{
			Discord: &discord.AlertProvider{},
		},
		ExternalEndpoints: []*endpoint.ExternalEndpoint{
			{
				Name:  "n",
				Group: "g",
				Token: "token",
				Alerts: []*alert.Alert{
					{
						Type:             alert.TypeDiscord,
						FailureThreshold: 2,
						SuccessThreshold: 2,
					},
				},
			},
		},
		Maintenance: &maintenance.Config{},
	}
	api := New(cfg)
	router := api.Router()
	scenarios := []struct {
		Name                           string
		Path                           string
		AuthorizationHeaderBearerToken string
		ExpectedCode                   int
	}{
		{
			Name:                           "no-token",
			Path:                           "/api/v1/endpoints/g_n/external?success=true",
			AuthorizationHeaderBearerToken: "",
			ExpectedCode:                   401,
		},
		{
			Name:                           "bad-token",
			Path:                           "/api/v1/endpoints/g_n/external?success=true",
			AuthorizationHeaderBearerToken: "Bearer bad-token",
			ExpectedCode:                   401,
		},
		{
			Name:                           "bad-key",
			Path:                           "/api/v1/endpoints/bad_key/external?success=true",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   404,
		},
		{
			Name:                           "bad-success-value",
			Path:                           "/api/v1/endpoints/g_n/external?success=invalid",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   400,
		},
		{
			Name:                           "good-token-success-true",
			Path:                           "/api/v1/endpoints/g_n/external?success=true",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   200,
		},
		{
			Name:                           "good-token-success-false",
			Path:                           "/api/v1/endpoints/g_n/external?success=false",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   200,
		},
		{
			Name:                           "good-token-success-false-again",
			Path:                           "/api/v1/endpoints/g_n/external?success=false",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   200,
		},
		{
			Name:                           "good-token-success-false-with-error",
			Path:                           "/api/v1/endpoints/g_n/external?success=false&error=service%20svc1%20went%20down",
			AuthorizationHeaderBearerToken: "Bearer token",
			ExpectedCode:                   200,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			request := httptest.NewRequest("POST", scenario.Path, http.NoBody)
			if len(scenario.AuthorizationHeaderBearerToken) > 0 {
				request.Header.Set("Authorization", scenario.AuthorizationHeaderBearerToken)
			}
			response, err := router.Test(request)
			if err != nil {
				return
			}
			defer response.Body.Close()
			if response.StatusCode != scenario.ExpectedCode {
				t.Errorf("%s %s should have returned %d, but returned %d instead", request.Method, request.URL, scenario.ExpectedCode, response.StatusCode)
			}
		})
	}
	t.Run("verify-end-results", func(t *testing.T) {
		endpointStatus, err := store.Get().GetEndpointStatus("g", "n", paging.NewEndpointStatusParams().WithResults(1, 10))
		if err != nil {
			t.Errorf("failed to get endpoint status: %s", err.Error())
			return
		}
		if endpointStatus.Key != "g_n" {
			t.Errorf("expected key to be g_n but got %s", endpointStatus.Key)
		}
		if len(endpointStatus.Results) != 4 {
			t.Errorf("expected 4 results but got %d", len(endpointStatus.Results))
		}
		if !endpointStatus.Results[0].Success {
			t.Errorf("expected first result to be successful")
		}
		if endpointStatus.Results[1].Success {
			t.Errorf("expected second result to be unsuccessful")
		}
		if endpointStatus.Results[2].Success {
			t.Errorf("expected third result to be unsuccessful")
		}
		if endpointStatus.Results[3].Success {
			t.Errorf("expected forth result to be unsuccessful")
		} else {
			errors := endpointStatus.Results[3].Errors
			if len(errors) != 1 {
				t.Errorf("expected 1 error in the forth result")
			} else if errors[0] != "service svc1 went down" {
				t.Errorf("wrong error in the forth result. expected: %s, got: %s", "service svc1 went down", errors[0])
			}
		}
		externalEndpointFromConfig := cfg.GetExternalEndpointByKey("g_n")
		if externalEndpointFromConfig.NumberOfFailuresInARow != 3 {
			t.Errorf("expected 3 failures in a row but got %d", externalEndpointFromConfig.NumberOfFailuresInARow)
		}
		if externalEndpointFromConfig.NumberOfSuccessesInARow != 0 {
			t.Errorf("expected 0 successes in a row but got %d", externalEndpointFromConfig.NumberOfSuccessesInARow)
		}
	})
}

func TestSanitize(t *testing.T) {
	scenarios := []struct {
		input  string
		output string
	}{
		{input: "good input", output: "good input"},
		{input: "http://link/to/error", output: "http://link/to/error"},
		{input: "<script alert(''); </script>", output: ""},
	}

	for _, s := range scenarios {
		s := s
		t.Run(s.input, func(t *testing.T) {
			t.Parallel()

			got := sanitizeInput(s.input)
			if got != s.output {
				t.Errorf("wrong sanitized output. expected: %s, got: %s", s.output, got)
			}
		})
	}
}
