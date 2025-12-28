import time
import threading
from typing import Callable, Optional

class S3Timer:
    def __init__(
        self,
        send_tester_present_cb: Callable[[], None],
        expiry_callback: Callable[[], None],
        s3_timeout: float = 5.0,
        auto_tp: bool = False,
        tp_lead: float = 1.0,
    ):
        self.s3_timeout = s3_timeout
        self.auto_tp = auto_tp
        self.tp_lead = tp_lead
        self._send_tp = send_tester_present_cb
        self._expiry_cb = expiry_callback
        self._lock = threading.Lock()
        self._last_activity = 0.0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        with self._lock:
            self._last_activity = time.time()
            if self._running: return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

    def reset(self) -> None:
        with self._lock:
            self._last_activity = time.time()

    def _run(self) -> None:
        check_interval = min(0.2, max(0.05, self.s3_timeout / 30.0))
        while not self._stop_event.is_set():
            with self._lock:
                if not self._running: break
                now = time.time()
                elapsed = now - self._last_activity
                do_expire = elapsed >= self.s3_timeout

            if do_expire:
                with self._lock:
                    self._running = False
                    self._stop_event.set()
                try:
                    self._expiry_cb()
                except: pass
                return
            
            self._stop_event.wait(timeout=check_interval)
