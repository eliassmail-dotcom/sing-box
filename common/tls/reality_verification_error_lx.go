package tls

// Typed authentication rejection: preserve the existing diagnostic text while
// letting the optional verified IP race distinguish it from transport errors.
type lxRealityVerificationFailure struct{}

func (lxRealityVerificationFailure) Error() string { return "reality verification failed" }
func (lxRealityVerificationFailure) LXIPRaceDefinitiveFailure() bool { return true }
