package libbox

import (
    "path/filepath"
    "strings"
    "testing"
)

func TestCommandSocketPath_DarwinPluginKitPluginContainer(t *testing.T) {
    base := "/var/mobile/Containers/Data/PluginKitPlugin/EDE70AC3-A2E3-4E0B-818F-08EFD7546806/Library/Application Support"
    tmp := "/var/mobile/Containers/Data/PluginKitPlugin/EDE70AC3-A2E3-4E0B-818F-08EFD7546806/tmp"
    for _, platform := range []string{"ios", "darwin"} {
        got, err := commandSocketPathFor(base, tmp, platform)
        if err != nil {
            t.Fatal(err)
        }
        want := filepath.Join(tmp, "command.sock")
        if got != want {
            t.Fatalf("%s: expected fallback %q, got %q", platform, want, got)
        }
        if len([]byte(got)) > darwinSocketNameMaxBytes {
            t.Fatalf("socket path is too long: %d", len([]byte(got)))
        }
    }
}

func TestCommandSocketPath_PreserveSharedAppGroupTransport(t *testing.T) {
    shared := "/var/mobile/Containers/Shared/AppGroup/12345678-1234-1234-1234-123456789ABC"
    got, err := commandSocketPathFor(shared, "/private/var/tmp", "ios")
    if err != nil {
        t.Fatal(err)
    }
    if want := filepath.Join(shared, "command.sock"); got != want {
        t.Fatalf("must preserve shared socket path: got %s want %s", got, want)
    }
}

func TestCommandSocketPath_RejectTooLongTemporaryDirectory(t *testing.T) {
    base := "/var/mobile/Containers/Data/PluginKitPlugin/" + strings.Repeat("a", 100)
    _, err := commandSocketPathFor(base, "/too/"+strings.Repeat("b", 150), "ios")
    if err == nil || !strings.Contains(err.Error(), "too long") {
        t.Fatalf("expected actionable Unix socket path error, got %v", err)
    }
}

func TestCommandSocketPath_NonDarwinUnchanged(t *testing.T) {
    base := "/long/" + strings.Repeat("z", 200)
    got, err := commandSocketPathFor(base, "/short", "linux")
    if err != nil {
        t.Fatal(err)
    }
    if want := filepath.Join(base, "command.sock"); got != want {
        t.Fatalf("non-Darwin path changed: got %s, expected %s", got, want)
    }
}
