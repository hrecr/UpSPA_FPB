package api

import (
	"net/http"
)

// NewRouter is the central HTTP router for the service.
// It maps each incoming request path to the correct handler.
func NewRouter() http.Handler {
	// Use the standard Go 1.22 ServeMux router.
	mux := http.NewServeMux()

	// 1. System health
	mux.HandleFunc("GET /v1/health", handleHealth)

	// 2. Setup (Pi1)
	mux.HandleFunc("POST /v1/setup", handleSetupCreate)
	mux.HandleFunc("GET /v1/setup/{uid_b64}", handleSetupGet)

	// 3. Cryptographic evaluation (Pi2)
	mux.HandleFunc("POST /v1/toprf/eval", handleToprfEval)

	// 4. Record management (Pi3, Pi4)
	mux.HandleFunc("POST /v1/records", handleRecordCreate)
	mux.HandleFunc("GET /v1/records/{suid_b64}", handleRecordGet)
	mux.HandleFunc("PUT /v1/records/{suid_b64}", handleRecordUpdate)
	mux.HandleFunc("DELETE /v1/records/{suid_b64}", handleRecordDelete)

	// 5. Password update (Pi5)
	mux.HandleFunc("POST /v1/password-update", handlePasswordUpdate)

	// Wrap the router with middleware.
	// Order matters: request ID -> logging -> panic recovery -> route handling.
	handler := RequestIDMiddleware(LoggingMiddleware(RecoverMiddleware(mux)))

	return handler
}

// ---------------------------------------------------------
// Handler functions
// ---------------------------------------------------------

// Only the health handler is fully implemented here because it does not require the database.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Return the expected health response payload.
	WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// The remaining handlers are placeholders for future implementation.
// Until then, they return a 501 Not Implemented response.

func handleSetupCreate(w http.ResponseWriter, r *http.Request) {
	// Reuse the shared JSON error helper.
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleSetupGet(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleToprfEval(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleRecordCreate(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleRecordGet(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleRecordUpdate(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}

func handlePasswordUpdate(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This feature is not implemented yet.", nil)
}