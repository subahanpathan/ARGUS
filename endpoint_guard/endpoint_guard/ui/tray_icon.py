import subprocess
import threading
import webbrowser
from typing import Optional

from PIL import Image, ImageDraw
import pystray

from ..engine.orchestrator import EndpointGuardOrchestrator


def create_tray_icon_image() -> Image.Image:
    """Generates an in-memory 64x64 shield icon."""
    img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Draw dark circular shield with cyan border
    draw.ellipse((4, 4, 60, 60), fill=(11, 15, 25), outline=(6, 182, 212), width=3)
    # Inner green active dot
    draw.ellipse((22, 22, 42, 42), fill=(16, 185, 129))
    return img


class TrayIcon:
    """Windows System Tray Icon providing status, panic isolation, and quick dashboard access."""

    def __init__(self, orchestrator: EndpointGuardOrchestrator):
        self.orchestrator = orchestrator
        self.icon: Optional[pystray.Icon] = None
        self._thread: Optional[threading.Thread] = None

    def _open_dashboard(self, icon, item) -> None:
        host = self.orchestrator.config.get("dashboard", "host", "127.0.0.1")
        port = self.orchestrator.config.get("dashboard", "port", 8443)
        webbrowser.open(f"http://{host}:{port}")

    def _trigger_panic(self, icon, item) -> None:
        self.orchestrator.response_engine.panic_isolate()
        self.show_notification("PANIC ISOLATION ACTIVE", "All external network traffic has been blocked!")

    def _restore_network(self, icon, item) -> None:
        self.orchestrator.response_engine.panic_restore()
        self.show_notification("Isolation Lifted", "Network communication restored.")

    def _exit(self, icon, item) -> None:
        if self.icon:
            self.icon.stop()
        self.orchestrator.stop()

    def show_notification(self, title: str, message: str) -> None:
        """Displays Windows balloon/toast notification."""
        if self.icon and hasattr(self.icon, "notify"):
            try:
                self.icon.notify(message, title)
                return
            except Exception:
                pass

        # Fallback to PowerShell balloon tip
        try:
            ps_script = f"""
            [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
            $notify = New-Object System.Windows.Forms.NotifyIcon
            $notify.Icon = [System.Drawing.SystemIcons]::Shield
            $notify.Visible = $True
            $notify.ShowBalloonTip(5000, '{title}', '{message}', [System.Windows.Forms.ToolTipIcon]::Warning)
            Start-Sleep -Seconds 1
            $notify.Dispose()
            """
            subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def run(self) -> None:
        menu = pystray.Menu(
            pystray.MenuItem("Endpoint Guard: ACTIVE", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open SOC Dashboard", self._open_dashboard),
            pystray.MenuItem("⚠ PANIC: Sever Connections", self._trigger_panic),
            pystray.MenuItem("✔ RESTORE: Re-enable Network", self._restore_network),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._exit),
        )
        self.icon = pystray.Icon("EndpointGuard", create_tray_icon_image(), "Endpoint Guard - Protected", menu)
        self.icon.run()

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.run, name="TrayIconThread", daemon=True)
        self._thread.start()
