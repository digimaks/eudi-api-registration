package eudiapiregistration

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-api-registration/internal/registrydb"
)

// TestAppAccessors boots NewTestApp (New + init) and asserts every accessor
// New/init is supposed to have populated is non-nil. This service's App only
// ever has Config/DB/Store to assert — no Valkey, keys, trust anchors,
// sessions, checker, notifier, mgmt client, deletion flow, or OIDC
// authenticator.
func TestAppAccessors(t *testing.T) {
	app := NewTestApp(t)

	qt.Assert(t, qt.IsNotNil(app.Config()))
	qt.Assert(t, qt.IsNotNil(app.DB()))
	qt.Assert(t, qt.IsNotNil(app.Store()))
}

// TestAppConfigPanicsWhenNotLoaded exercises Config()'s fail-closed panic
// branch: a handler calling Config() before New() has completed (or on a
// zero-value App) is a programming bug, not a runtime condition to recover
// from silently.
func TestAppConfigPanicsWhenNotLoaded(t *testing.T) {
	defer func() {
		r := recover()
		qt.Assert(t, qt.IsNotNil(r))
	}()

	a := &App{}
	a.Config()
}

// TestAppStoreSeam exercises the test-only SetStoreForTest seam (testing.go's
// raison d'être: unit tests never dial Postgres) round-trips correctly
// through the Store() accessor. NewTestApp already installs a Fake by
// default (testing.go); this asserts a SECOND, test-owned Fake instance can
// still be swapped in afterward.
func TestAppStoreSeam(t *testing.T) {
	app := NewTestApp(t)

	fake := registrydb.NewFake()
	app.SetStoreForTest(fake)
	qt.Assert(t, qt.Equals[registrydb.Store](app.Store(), fake))
}
