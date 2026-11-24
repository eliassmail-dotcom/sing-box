package group

import "testing"

func TestMigrateSmartSelection(t *testing.T) {
	const old = "Авто · База → Белые"
	const smart = "Авто · Умный"
	for _, tc := range []struct {
		group, selected string
		tags []string
		want string
	}{
		{"Стратегия", old, []string{"base", smart}, smart},
		{"Стратегия", old, []string{"base", old, smart}, old},
		{"Стратегия", old, []string{"base"}, old},
		{"other", old, []string{smart}, old},
		{"Стратегия", "base", []string{"base", smart}, "base"},
	} {
		if got := migrateSmartSelection(tc.group, tc.selected, tc.tags); got != tc.want {
			t.Errorf("migrate %q / %q: got %q, want %q", tc.group, tc.selected, got, tc.want)
		}
	}
}
