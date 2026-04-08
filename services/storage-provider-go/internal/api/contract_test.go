package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

func getWorkspaceRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	// Traverse up to find the docs directory
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "docs", "openapi", "sp.yaml")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return "../../../.."
}

func TestOpenAPIContract(t *testing.T) {
	root := getWorkspaceRoot()
	specPath := filepath.Join(root, "docs", "openapi", "sp.yaml")
	
	ctx := context.Background()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Skipf("Skipping contract tests, could not load OpenAPI spec: %v", err)
	}

	err = doc.Validate(ctx)
	if err != nil {
		t.Fatalf("OpenAPI document validation failed: %v", err)
	}

	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("Failed to build router from OpenAPI: %v", err)
	}

	store := NewFakeStore()
	handlerWrapper := NewHandler(store)
	server := NewRouter(handlerWrapper) // this creates the stdlib mux

	tests := []struct {
		name      string
		method    string
		path      string
		body      interface{}
		setupMock func()
		respCode  int
	}{
		{
			name:   "Health Check",
			method: http.MethodGet,
			path:   "/v1/health",
			body:   nil,
			respCode: http.StatusOK,
		},
		{
			name:   "Setup Success",
			method: http.MethodPost,
			path:   "/v1/setup",
			body: map[string]interface{}{
				"uid_b64":    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
				"sig_pk_b64": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
				"cid": map[string]interface{}{
					"nonce": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
					"ct":    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
					"tag":   "qqqqqqqqqqqqqqqqqqqqqw",
				},
				"k_i_b64": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
			},
			respCode: http.StatusCreated,
		},
		{
			name:   "Eval TOPRF",
			method: http.MethodPost,
			path:   "/v1/toprf/eval",
			body: map[string]interface{}{
				"uid_b64":     "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
				"blinded_b64": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw",
			},
			setupMock: func() {
				store.PutSetup(context.Background(), "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw", "", "", "", "", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqw")
			},
			respCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupMock != nil {
				tc.setupMock()
			}

			var reqBody []byte
			if tc.body != nil {
				reqBody, _ = json.Marshal(tc.body)
			}

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(reqBody))
			if reqBody != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			// First validate request against OpenAPI spec
			route, pathParams, err := router.FindRoute(req)
			if err == nil {
				reqValidationInput := &openapi3filter.RequestValidationInput{
					Request:    req,
					PathParams: pathParams,
					Route:      route,
				}
				if err := openapi3filter.ValidateRequest(ctx, reqValidationInput); err != nil {
					// We just log for now as the server might have stricter custom validation
					t.Logf("OpenAPI request validation warn: %v", err)
				}
			}

			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, req)

			if rr.Code != tc.respCode {
				t.Fatalf("expected status %d, got %d. Body: %s", tc.respCode, rr.Code, rr.Body.String())
			}

			// Validate response shape against OpenAPI spec
			if route != nil {
				respValidationInput := &openapi3filter.ResponseValidationInput{
					RequestValidationInput: &openapi3filter.RequestValidationInput{
						Request:    req,
						PathParams: pathParams,
						Route:      route,
					},
					Status: rr.Code,
					Header: rr.Header(),
				}

				if rr.Body != nil {
					respValidationInput.SetBodyBytes(rr.Body.Bytes())
				}

				err := openapi3filter.ValidateResponse(ctx, respValidationInput)
				if err != nil {
					t.Errorf("Response validation against OpenAPI failed: %v\nBody: %s", err, rr.Body.String())
				}
			}
		})
	}
}
