package routes

import (
	"context"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// healthz is liveness only — no dependency probing (that is /readyz). Tiny
// body + skip access log.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.JSON(map[string]string{"status": "ok"})
}

// readyz fails closed on the ONE dependency this service has: Postgres.
// There is no Valkey to probe.
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	probe, cancel := context.WithTimeout(ctx.Context(), 2*time.Second)
	defer cancel()

	if err := r.DB().Ping(probe); err != nil {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.JSON(map[string]any{"status": "degraded", "components": map[string]string{"postgres": "unreachable"}})
		return
	}
	ctx.JSON(map[string]string{"status": "ok"})
}
