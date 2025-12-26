```python
# s3_timer.py
import time                          # Used for time measurement (timeouts, elapsed time)
import threading                     # Used to run the timer monitoring loop in a background thread
from typing import Callable, Optional  # Type hints for callback functions and optional thread object

class S3Timer:
    """
    S3 (session timeout) timer helper.

    Purpose:
    - Track "last activity" time.
    - If no activity happens for s3_timeout seconds, trigger expiry_callback().
    - Optionally auto-send TesterPresent before expiry to keep the session alive.

    Common UDS context:
    - Many ECUs drop diagnostic sessions after an inactivity timeout (S3).
    - TesterPresent (0x3E 0x00) is typically used to keep the session alive.
    """

    def __init__(
        self,
        send_tester_present_cb: Callable[[], None],
        expiry_callback: Callable[[], None],
        s3_timeout: float = 8.0,
        auto_tp: bool = True,
        tp_lead: float = 1.0,
    ):
        """
        send_tester_present_cb:
            A function that sends a TesterPresent request (UDS service 0x3E, subfunction 0x00).
            This class does not implement sending; it calls this callback.

        expiry_callback:
            A function called when the S3 timeout expires (i.e., no activity for s3_timeout seconds).

        s3_timeout:
            Timeout duration in seconds. If elapsed time since last activity >= s3_timeout, session is expired.

        auto_tp:
            If True, automatically send TesterPresent shortly before expiry.

        tp_lead:
            How many seconds before expiry to auto-send TesterPresent.
            Example: s3_timeout=8, tp_lead=1 → send TP when time_left is between 0 and 1 second.
        """
        # Ensure meaningful timer values (prevents negative/invalid timeouts)
        assert s3_timeout > 0
        assert tp_lead >= 0

        # Store configuration parameters
        self.s3_timeout = s3_timeout
        self.auto_tp = auto_tp
        self.tp_lead = tp_lead

        # Store callback references
        self._send_tp = send_tester_present_cb
        self._expiry_cb = expiry_callback

        # Thread-safety tools:
        # - _lock protects shared variables accessed by multiple threads
        # - _stop_event is used to stop the background loop cleanly
        self._lock = threading.Lock()

        # Last time activity happened (used to calculate elapsed time)
        self._last_activity = 0.0

        # Running state flags and thread handle
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the S3 timer."""
        with self._lock:
            # Mark "activity now" at start so the timer begins counting from now
            self._last_activity = time.time()

            # Prevent starting multiple threads if already running
            if self._running:
                return

            # Set running state and launch background monitoring thread
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the S3 timer."""
        with self._lock:
            # Signal the loop to stop and update running state
            self._running = False
            self._stop_event.set()

        # Join thread briefly to avoid leaving a running thread behind
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

    def reset(self) -> None:
        """Reset last activity time."""
        # Called when "activity" happens (e.g., any diagnostic request/response)
        with self._lock:
            self._last_activity = time.time()

    def send_tester_present(self) -> None:
        """Send TesterPresent manually and reset timer."""
        # Sends TP via callback, then resets activity time even if callback raises
        try:
            self._send_tp()
        finally:
            self.reset()

    def _run(self) -> None:
        """Internal loop monitoring S3."""
        # Determine how often to check the timer.
        # - Never slower than 0.2s
        # - Never faster than 0.05s
        # - Otherwise scale with timeout (timeout/30) for balanced CPU usage
        check_interval = min(0.2, max(0.05, self.s3_timeout / 30.0))

        while not self._stop_event.is_set():
            # Compute time_left and expiry conditions inside the lock
            # so reads of shared state are consistent
            with self._lock:
                if not self._running:
                    break

                now = time.time()
                elapsed = now - self._last_activity          # Seconds since last activity
                time_left = self.s3_timeout - elapsed        # Seconds until expiry

                # Decide actions outside the lock (avoid holding lock during callbacks)
                pass_send = self.auto_tp and 0 < time_left <= self.tp_lead
                do_expire = elapsed >= self.s3_timeout

            # Auto-send TesterPresent if enabled and close to expiry
            if pass_send:
                try:
                    self._send_tp()
                except Exception as e:
                    # Callback errors should not crash the timer thread
                    print(f"[S3Timer] Warning: send_tester_present_cb raised: {e}")
                # Reset timer after sending TP (keeps session alive)
                self.reset()

            # If expired, stop and call expiry callback once
            if do_expire:
                with self._lock:
                    self._running = False
                    self._stop_event.set()
                try:
                    self._expiry_cb()
                except Exception as e:
                    # Expiry callback errors should not crash the program
                    print(f"[S3Timer] Warning: expiry_callback raised: {e}")
                return

            # Sleep/wait until next check, but allow stop_event to interrupt the wait
            self._stop_event.wait(timeout=check_interval)
```
