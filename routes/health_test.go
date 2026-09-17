package routes

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	eudiapiregistration "github.com/dativa-lv/eudi-api-registration"
)

func testApp(t testing.TB) *azugo.TestApp {
	t.Helper()
	app := eudiapiregistration.NewTestApp(t)
	err := Init(app)
	qt.Assert(t, qt.IsNil(err))
	return azugo.NewTestApp(app.App)
}

func TestHealthzOK(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}

// TestReadyzFailsClosedWhenDepsDown: negative first (TDD) — Postgres is the
// ONE dependency this service has (no Valkey), and NewTestApp
// (testing.go) deliberately points POSTGRES_DSN at an unreachable
// placeholder (init()'s pgxpool.New never dials eagerly, so booting is
// harmless; SetStoreForTest only swaps Store(), never DB()) ⇒ readyz must
// fail closed with 503, never "ready by default". No test exercises the
// positive/OK path: that would need a real reachable Postgres, which this
// unit-test harness deliberately never stands up.
func TestReadyzFailsClosedWhenDepsDown(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
}

func TestCorrelationHeaderEchoed(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Get("/healthz", tc.WithHeader("X-Correlation-ID", "01TESTCID"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Correlation-ID")), "01TESTCID"))
}
