// Quickshell component (an Item): exposes the latest toriid status as `status`.
// Works the same in any Quickshell-based shell (DankMaterialShell plugins, custom bars).
import QtQuick
import Quickshell
import Quickshell.Io

Item {
    id: root
    property var status: ({ state: "unknown", mode: "unknown", tunnel: "", network: { ssid: "" } })
    readonly property bool protectedNow: status.state === "protected"

    Process {
        id: watcher
        running: true
        command: ["torii", "watch"]
        stdout: SplitParser {
            onRead: line => {
                try { root.status = JSON.parse(line) } catch (e) {}
            }
        }
        // Restart if the stream ends (daemon reinstall, etc.)
        onExited: restart.start()
    }
    Timer { id: restart; interval: 3000; onTriggered: watcher.running = true }

    function up()     { Quickshell.execDetached(["torii", "up"]) }
    function portal() { Quickshell.execDetached(["torii", "portal"]) }
}
