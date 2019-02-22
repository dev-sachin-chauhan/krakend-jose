package jose

import (
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
)

// Rejecter defines the interface for the components responsible for rejecting tokens.
type Rejecter interface {
	Reject(map[string]interface{}) bool
}

// RejecterFunc is an adapter to use functions as rejecters
type RejecterFunc func(map[string]interface{}) bool

// Reject calls r(v)
func (r RejecterFunc) Reject(v map[string]interface{}) bool { return r(v) }

// FixedRejecter is a rejecter that always returns the same bool response
type FixedRejecter bool

// Reject returns f
func (f FixedRejecter) Reject(_ map[string]interface{}) bool { return bool(f) }

// RejecterFactory is a builder for rejecters
type RejecterFactory interface {
	New(logging.Logger, *config.EndpointConfig) Rejecter
}

// RejecterFactoryFunc is an adapter to use a function as rejecter factory
type RejecterFactoryFunc func(logging.Logger, *config.EndpointConfig) Rejecter

// New calls f(l, cfg)
func (f RejecterFactoryFunc) New(l logging.Logger, cfg *config.EndpointConfig) Rejecter {
	return f(l, cfg)
}

// NopRejecterFactory is a factory returning rejecters accepting all the tokens
type NopRejecterFactory struct{}

// New returns a fixed rejecter that accepts all the tokens
func (NopRejecterFactory) New(_ logging.Logger, _ *config.EndpointConfig) Rejecter {
	return FixedRejecter(false)
}
