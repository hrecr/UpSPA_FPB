# Week 4: Contract Tests & API Guide

## How to Add a New Endpoint
1. **Contract & Models**: Add the endpoint to `docs/openapi/sp.yaml` and define structs in `types.go`.
2. **Routes & Handler**: Map the route in `routes.go` and write the handler in the `internal/api/` folder.
3. **Tests**: Update the `Store` interface if needed, and write tests in `api_unit_test.go`.

## Error Mapping Rules
Always use the standardized JSON format via `WriteError`:
* **400 Bad Request**: Invalid JSON, bad base64, or wrong byte lengths.
* **401 Unauthorized**: Invalid Ed25519 signatures.
* **404 Not Found**: Unknown resource (ID not found).
* **409 Conflict**: Duplicate records or replay attacks (old timestamps).
* **500 Internal Server Error**: Database issues or panics.

## Logging Hygiene Checklist
* [ ] **NO SECRETS**: Never log `uid_b64`, `k_i_b64`, `cid`, `cj`, or signatures.
* [ ] **Structured Logs**: Use `slog` with consistent key-value pairs.
* [ ] **Tracing & Errors**: Always include request IDs and ensure panics are handled gracefully.
