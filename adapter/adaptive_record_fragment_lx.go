package adapter

import "context"

type lxAdaptiveRecordFragmentRaceKey struct{}
type lxAdaptiveRecordFragmentModeKey struct{}

func ContextWithAdaptiveRecordFragmentRaceLx(ctx context.Context) context.Context {
	return context.WithValue(ctx, lxAdaptiveRecordFragmentRaceKey{}, true)
}

func AdaptiveRecordFragmentRaceLx(ctx context.Context) bool {
	enabled, _ := ctx.Value(lxAdaptiveRecordFragmentRaceKey{}).(bool)
	return enabled
}

func ContextWithAdaptiveRecordFragmentModeLx(ctx context.Context, fragmented bool) context.Context {
	return context.WithValue(ctx, lxAdaptiveRecordFragmentModeKey{}, fragmented)
}

func AdaptiveRecordFragmentModeLx(ctx context.Context) bool {
	fragmented, _ := ctx.Value(lxAdaptiveRecordFragmentModeKey{}).(bool)
	return fragmented
}
