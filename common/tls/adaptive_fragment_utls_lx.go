//go:build with_utls

package tls

// Invoked on the per-handshake clone only; never change the base config.
func (e *RealityClientConfig) setAdaptiveRecordFragmentLx() {
	e.uClient.recordFragment = true
}
