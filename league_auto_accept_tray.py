# league_auto_accept_tray.py
# LoL/TFT auto-accept (no WebSocket; fast 250ms polling).
# - Finds LeagueClientUx.exe args (--app-port / --remoting-auth-token) via psutil
# - Verifies it's the real League LCU (not Riot launcher)
# - Polls /lol-matchmaking/v1/ready-check every 250ms and POSTs /accept immediately
# - Tray: Pause/Resume, Open Log, Quit
# - Logs: %LOCALAPPDATA%\LeagueAutoAccept\accept.log
# NOTE: Automation may violate Riot ToS. Use at your own risk.

import base64
import json
import os
import time
import logging
import threading
import requests
import psutil
import pathlib
import sys
import ctypes
from dataclasses import dataclass
from typing import Optional

import pystray
from pystray import MenuItem as Item
from PIL import Image, ImageDraw

# ===================== Config =====================
LOG_DIR = pathlib.Path(os.getenv("LOCALAPPDATA", ".")) / "LeagueAutoAccept"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "accept.log"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
READY_EP  = "/lol-matchmaking/v1/ready-check"
ACCEPT_EP = "/lol-matchmaking/v1/ready-check/accept"
LOGIN_EP  = "/lol-login/v1/session"            # only on League LCU
POLL_INTERVAL_SEC = 0.25       # 250ms polling
RESCAN_SEC = 2.0               # when client not found / idle
HTTP_TIMEOUT = 1.0             # snappy local calls

# ===================== Logging =====================
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout) if sys.stdout and sys.stdout.isatty() else logging.NullHandler(),
    ],
)
requests.packages.urllib3.disable_warnings()

# Crisp tray icon (harmless if this fails)
if os.name == "nt":
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

# ===================== LCU discovery =====================
@dataclass
class LCUConn:
    port: int
    token: str

def find_port_pw_from_process():
    """
    Read LeagueClientUx.exe cmdline: --app-port=XXXXX --remoting-auth-token=YYYY
    Returns (port, token) or (None, None).
    """
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name != "leagueclientux.exe":
                continue
            cmd = proc.info.get("cmdline") or []
            port = None
            token = None
            for arg in cmd:
                if arg.startswith("--app-port="):
                    port = int(arg.split("=", 1)[1])
                elif arg.startswith("--remoting-auth-token="):
                    token = arg.split("=", 1)[1]
            if port and token:
                return port, token
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return None, None

def fallback_lockfile():
    """
    Fallback to %LOCALAPPDATA%\League of Legends\lockfile
    Returns (port, token) or (None, None).
    """
    p = pathlib.Path(os.getenv("LOCALAPPDATA", "")) / "League of Legends" / "lockfile"
    try:
        if p.exists():
            parts = p.read_text(encoding="utf-8", errors="ignore").strip().split(":")
            if len(parts) == 5 and "LeagueClient" in parts[0]:
                return int(parts[2]), parts[3]
    except Exception:
        pass
    return None, None

def get_connection() -> Optional[LCUConn]:
    port, token = find_port_pw_from_process()
    if not port:
        port, token = fallback_lockfile()
    if port and token:
        return LCUConn(port=port, token=token)
    return None

# ===================== LCU helpers =====================
def auth_header(token: str):
    b = base64.b64encode(f"riot:{token}".encode()).decode()
    return {"Authorization": f"Basic {b}"}

def is_league_lcu(base_url: str, headers) -> bool:
    """True only when attached to the real League client (not Riot launcher)."""
    try:
        r = requests.get(base_url + LOGIN_EP, headers=headers, verify=False, timeout=HTTP_TIMEOUT)
        return r.status_code in (200, 201, 202, 204)
    except requests.RequestException:
        return False

def get_ready(base_url: str, headers):
    try:
        r = requests.get(base_url + READY_EP, headers=headers, verify=False, timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            return None
        if r.status_code in (401, 403):
            raise PermissionError("Auth expired")
        r.raise_for_status()
        return r.json()
    except requests.RequestException:
        return None

def accept_ready(base_url: str, headers):
    try:
        r = requests.post(base_url + ACCEPT_EP, headers=headers, verify=False, timeout=HTTP_TIMEOUT)
        if r.status_code in (401, 403):
            raise PermissionError("Auth expired")
        logging.info(f"POST {ACCEPT_EP} -> {r.status_code}")
        return r.ok
    except requests.RequestException as e:
        logging.warning(f"Accept error: {e}")
        return False

# ===================== Tray icon =====================
ICON_NAMES = ("app.ico", "app.png")

def _candidate_icon_paths():
    # 1) Folder of the executable (PyInstaller onefile)
    if getattr(sys, "frozen", False):
        yield pathlib.Path(sys.executable).with_name("app.ico")
        yield pathlib.Path(sys.executable).with_name("app.png")
    # 2) Folder of this script (__file__)
    if "__file__" in globals():
        yield pathlib.Path(__file__).with_name("app.ico")
        yield pathlib.Path(__file__).with_name("app.png")
    # 3) Current working directory
    cwd = pathlib.Path.cwd()
    for n in ICON_NAMES:
        yield cwd / n
    # 4) App data dir (where logs live)
    for n in ICON_NAMES:
        yield LOG_DIR / n

def _load_icon_file() -> Optional[Image.Image]:
    for p in _candidate_icon_paths():
        if p.exists():
            try:
                img = Image.open(p).convert("RGBA")
                # Fit tray nicely (Windows uses 16x16 logical; scaling is handled by the shell)
                return img.resize((16, 16), Image.LANCZOS)
            except Exception:
                continue
    return None

def make_tray_icon(active: bool) -> Image.Image:
    """Use custom icon if provided; otherwise draw a green/gray dot."""
    img = _load_icon_file()
    if img is not None:
        return img
    size = (16, 16)
    img = Image.new("RGBA", size, (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (0, 180, 0) if active else (128, 128, 128)
    d.ellipse((2, 2, 14, 14), fill=color)
    return img

# ===================== Worker =====================
class AutoAcceptor(threading.Thread):
    def __init__(self, pause_event: threading.Event, stop_event: threading.Event, status_cb):
        super().__init__(daemon=True)
        self.pause_event = pause_event
        self.stop_event = stop_event
        self.status_cb = status_cb
        self.current_conn: Optional[LCUConn] = None

    def run(self):
        backoff = 1.0
        while not self.stop_event.is_set():
            if self.pause_event.is_set():
                self.status_cb("Paused")
                time.sleep(0.25)
                continue

            try:
                conn = get_connection()
                if not conn:
                    self.status_cb("Waiting for League client")
                    time.sleep(RESCAN_SEC)
                    continue

                # If port/token changed, announce
                if (not self.current_conn or
                    self.current_conn.port != conn.port or
                    self.current_conn.token != conn.token):
                    self.current_conn = conn
                    logging.info(f"Attached to LCU (port={conn.port})")
                    backoff = 1.0

                base_url = f"https://127.0.0.1:{conn.port}"
                headers = auth_header(conn.token)

                # Make sure it's the actual League LCU
                if not is_league_lcu(base_url, headers):
                    self.status_cb("Client idle / not League yet")
                    time.sleep(RESCAN_SEC)
                    continue

                # Poll loop
                self.status_cb(f"Polling @ {conn.port}")
                while not self.stop_event.is_set() and not self.pause_event.is_set():
                    try:
                        st = get_ready(base_url, headers)
                    except PermissionError:
                        # Token/port rotated; break to rediscover
                        logging.info("Auth rotated; rediscovering LCU…")
                        break

                    if st:
                        state = str(st.get("state", "")).lower()
                        resp  = str(st.get("playerResponse", "")).lower()
                        if state in ("inprogress", "pending") and resp not in ("accepted", "declined"):
                            try:
                                if accept_ready(base_url, headers):
                                    self.status_cb("Accepted")
                                    time.sleep(0.3)  # avoid rapid double-posts
                                    continue
                            except PermissionError:
                                logging.info("Auth rotated during accept; rediscovering…")
                                break
                    time.sleep(POLL_INTERVAL_SEC)

            except Exception as e:
                logging.warning(f"Worker error: {e}")
                time.sleep(backoff)
                backoff = min(backoff * 1.6, 10.0)

# ===================== Tray app =====================
class TrayApp:
    def __init__(self):
        self.pause_event = threading.Event()
        self.stop_event  = threading.Event()
        self.status_text = "Idle"

        self.icon = pystray.Icon("LoL Auto Accept", make_tray_icon(True), "LoL Auto Accept")
        self.icon.menu = pystray.Menu(
            Item(self._status_label, None, enabled=False),
            Item(self._pause_resume_label, self.toggle_pause),
            Item("Open Log", self.open_log),
            Item("Quit", self.quit),
        )

        self.worker = AutoAcceptor(self.pause_event, self.stop_event, self.set_status)
        self.worker.start()

    # ---- label callbacks (pystray passes the item) ----
    def _status_label(self, item):
        return f"Status: {self.status_text}"

    def _pause_resume_label(self, item):
        return "Pause" if not self.pause_event.is_set() else "Resume"

    # ---- actions (pystray passes icon, item) ----
    def toggle_pause(self, icon, item):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.set_status("Resumed")
        else:
            self.pause_event.set()
            self.set_status("Paused")

    def open_log(self, icon, item):
        try:
            os.startfile(str(LOG_FILE))
        except Exception as e:
            logging.warning(f"Cannot open log: {e}")

    def quit(self, icon, item):
        self.set_status("Stopping…")
        self.stop_event.set()
        try:
            self.worker.join(timeout=2.0)
        except Exception:
            pass
        self.icon.stop()

    # ---- status updater ----
    def set_status(self, text: str):
        self.status_text = text
        # update tray title & icon
        self.icon.title = f"LoL Auto Accept — {text}"
        self.icon.icon = make_tray_icon(not self.pause_event.is_set())
        # rebuild menu so label reflects new text
        self.icon.menu = pystray.Menu(
            Item(self._status_label, None, enabled=False),
            Item(self._pause_resume_label, self.toggle_pause),
            Item("Open Log", self.open_log),
            Item("Quit", self.quit),
        )

    def run(self):
        self.icon.run()

# ===================== Main =====================
def main():
    # simple single-instance lock
    lock_path = LOG_DIR / "instance.lock"
    try:
        if lock_path.exists():
            lock_path.unlink(missing_ok=True)
        lock_path.write_text(str(os.getpid()))
    except Exception:
        pass

    TrayApp().run()

if __name__ == "__main__":
    main()
