// Package registrydb calls the registry- and audit-schema SECURITY DEFINER
// procedures via the JSONB envelope. eudi-api-registration never touches
// registry/audit tables directly — connect as registration_api_public, an
// EXECUTE-only role with no table/sequence grants.
//
// This is the counterpart to the session service's internal/registrydb —
// same bridge shape, copied deliberately rather than shared: the session
// service's registrydb is internal to ITS OWN module and this service cannot
// import it (see repo.go's package doc for the cross-module JSON-shape
// contract this implies).
package registrydb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type envelope struct {
	Result  string          `json:"result"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// resultError maps a DB envelope result code onto the kit HTTP error taxonomy.
// Procedures emit house-style `<domain>:<reason>` — this service produces two
// domains, `registry:*` and `audit:*` — but errors.FromResultCode keys off
// the kit taxonomy `err:<domain>:<reason>`; it needs the `err:` prefix + 3
// segments to map `:not_found` → 404 (else 4xx/5xx). Bridge the two here so
// e.g. `registry:not_found` surfaces as err:registry:not_found (404) rather
// than an opaque 500. An empty code is not an error.
func resultError(code string) error {
	if code == "" {
		return nil
	}
	return pkerrors.FromResultCode("err:" + code)
}

func parseEnvelope(b []byte) (json.RawMessage, string, error) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, "", fmt.Errorf("registrydb: malformed envelope: %w", err)
	}
	switch e.Result {
	case "success":
		return e.Data, "", nil
	case "error":
		return nil, e.Code, nil
	default:
		return nil, "", fmt.Errorf("registrydb: unknown envelope result %q", e.Result)
	}
}

// call invokes one procedure. proc MUST be one of the fixed constants in
// repo.go — never caller input (no SQL injection surface).
func call(ctx context.Context, pool *pgxpool.Pool, proc string, in any) (json.RawMessage, error) {
	pi, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("registrydb: marshal pi_data: %w", err)
	}
	var out []byte
	err = pool.QueryRow(ctx, "call "+proc+"($1, $2)", pi, nil).Scan(&out)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			// Pattern B: the exception message IS the structured envelope.
			_, code, perr := parseEnvelope([]byte(pgErr.Message))
			if perr != nil {
				return nil, perr
			}
			return nil, resultError(code)
		}
		return nil, fmt.Errorf("registrydb: %s: %w", proc, err)
	}
	data, code, err := parseEnvelope(out)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return nil, resultError(code) // :not_found → 404, else 4xx/5xx
	}
	return data, nil
}
