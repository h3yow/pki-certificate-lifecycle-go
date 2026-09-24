package pki

import "time"

// Clock abstracts time so validity conclusions are reproducible in tests.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// frozenClock returns a fixed instant and is used by tests for reproducible
// expiry / not-before conclusions.
type frozenClock struct{ t time.Time }

func (c frozenClock) Now() time.Time { return c.t }
