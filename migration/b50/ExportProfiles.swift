import Foundation

// Compile this file together with the *actual* pinned Apple profile sources.
// No Libbox stubs, no credentials, no runtime connections.
@main
struct ExportB50Profiles {
    static func main() throws {
        let dir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let source = """
        {
          "outbounds": [
            {"type":"selector","tag":"Стратегия","outbounds":["Авто · Базовая"],"default":"Авто · Базовая"},
            {"type":"urltest","tag":"Авто · Базовая","outbounds":["France"],"url":"https://example.org/health"},
            {"type":"vless","tag":"France","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001"},
            {"type":"urltest","tag":"Gemini+","outbounds":["Swiss (Gemini)","Austria (Gemini)"],"url":"https://example.org/generate_204","interval":"5s"},
            {"type":"vless","tag":"Swiss (Gemini)","server":"192.0.2.11","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002"},
            {"type":"vless","tag":"Austria (Gemini)","server":"192.0.2.12","server_port":443,"uuid":"00000000-0000-4000-8000-000000000003"},
            {"type":"selector","tag":"Gemini","outbounds":["Gemini • Chain • A","Gemini • Авто"],"default":"Gemini • Chain • A"},
            {"type":"urltest","tag":"Gemini • Chain • A","outbounds":["Legacy Chain"]},
            {"type":"chain","tag":"Legacy Chain","outbounds":["France","Swiss (Gemini)"]},
            {"type":"chain","tag":"Outer Chain","outbounds":["Legacy Chain","Austria (Gemini)"]}
          ],
          "route":{"final":"Стратегия","rules":[{"domain":["gemini.google.com"],"outbound":"Gemini"}]}
        }
        """
        for chains in [false, true] {
            for tuned in [false, true] {
                var profile = LXProfileSettings()
                profile.geminiChainsEnabled = chains
                if tuned { profile.applyResiliencePreset("antiblock") }
                var store = LXOverridesStore()
                store.profiles["42"] = profile
                let result = try LXProfileOverrides.apply(source, profileID: 42, storedJSON: store.encode())
                let name = "generated-\(chains)-\(tuned).json"
                try result.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
            }
        }
        // Native LX.37 must reject removed legacy fields explicitly.
        var bad = try JSONSerialization.jsonObject(with: Data(source.utf8)) as! [String: Any]
        var out = bad["outbounds"] as! [[String: Any]]
        let index = out.firstIndex { $0["tag"] as? String == "Legacy Chain" }!
        out[index]["idle_timeout"] = "5m"
        bad["outbounds"] = out
        try JSONSerialization.data(withJSONObject: bad).write(to: dir.appendingPathComponent("invalid-idle-timeout.json"))
        out[index].removeValue(forKey: "idle_timeout")
        out[index]["strip"] = true
        bad["outbounds"] = out
        try JSONSerialization.data(withJSONObject: bad).write(to: dir.appendingPathComponent("invalid-strip.json"))
    }
}
