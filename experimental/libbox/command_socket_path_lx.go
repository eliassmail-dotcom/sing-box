package libbox

import (
    "fmt"
    "os"
    "path/filepath"
    "runtime"
)

const (
    commandSocketFileName = "command.sock"
    // Darwin's sockaddr_un.sun_path has 104 bytes, including the trailing NUL.
    // Go's net.ListenUnix requires the complete UTF-8 path to fit.
    darwinSocketNameMaxBytes = 103
)

// commandSocketPathFor is shared by the gRPC server and client so they never
// disagree on the endpoint after a long-container-path fallback.
//
// In an App Group setup, the primary path normally fits and remains shared
// across the containing app and the Packet Tunnel. In isolated (GBox re-signed)
// PluginKitPlugin containers, Application Support can exceed the Darwin AF_UNIX
// path limit. Use the CURRENT PROCESS's private, writable TMPDIR in that case.
// This is intentionally not a cross-sandbox IPC bridge.
func commandSocketPathFor(basePath, tempDir, platform string) (string, error) {
    primary := filepath.Join(basePath, commandSocketFileName)
    if platform != "ios" && platform != "darwin" {
        return primary, nil
    }
    if len([]byte(primary)) <= darwinSocketNameMaxBytes {
        return primary, nil
    }

    // Use a short basename as well: the /private/var alias may add eight
    // bytes, so even tmp/command.sock can exceed Darwin's 103-byte limit.
    fallback := filepath.Join(tempDir, "c.sock")
    if len([]byte(fallback)) > darwinSocketNameMaxBytes {
        return "", fmt.Errorf(
            "command socket path too long for Darwin: base=%d bytes, tmp=%d bytes (limit %d); short writable TMPDIR required",
            len([]byte(primary)), len([]byte(fallback)), darwinSocketNameMaxBytes,
        )
    }
    return fallback, nil
}

func commandSocketPath() (string, error) {
    return commandSocketPathFor(sBasePath, os.TempDir(), runtime.GOOS)
}
