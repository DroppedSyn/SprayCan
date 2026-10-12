import os
import shutil
import sys
import threading
import time

import util.scan_events as _scan_events
import util.settings as settings


class StatusReporter:
    frames = ("|", "/", "-", "\\")

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.lock = threading.Lock()
        self.stop_event = None
        self.thread = None
        self.frame_index = 0
        self.task_name = ""
        self.phase = ""
        self.note = ""
        self.started_at = None
        self.last_rendered_length = 0

    def is_enabled(self):
        return (
            hasattr(self.stream, "isatty")
            and self.stream.isatty()
            and settings.get_verbosity() != "debug"
            and os.environ.get("TERM") not in (None, "", "dumb")
        )

    def start(self, task_name):
        if not self.is_enabled():
            return

        self.stop()
        self.task_name = task_name
        self.phase = ""
        self.note = ""
        self.started_at = time.time()
        self.frame_index = 0
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def set_phase(self, phase):
        with self.lock:
            self.phase = phase or ""

    def set_note(self, note):
        with self.lock:
            self.note = note or ""

    def clear_note(self):
        with self.lock:
            self.note = ""

    def clear_line(self):
        if not self.is_enabled():
            return
        with self.lock:
            self._clear_line_locked()

    def print_message(self, message):
        if not self.is_enabled():
            print(message)
            return
        with self.lock:
            self._clear_line_locked()
            print(message)
            self.stream.flush()

    def stop(self):
        if self.stop_event is None:
            return
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1.0)
        with self.lock:
            self._clear_line_locked()
        self.thread = None
        self.stop_event = None
        self.task_name = ""
        self.phase = ""
        self.note = ""
        self.started_at = None
        self.last_rendered_length = 0

    def _run(self):
        while self.stop_event is not None and not self.stop_event.is_set():
            with self.lock:
                self._render_locked()
            time.sleep(0.12)

    def _render_locked(self):
        frame = self.frames[self.frame_index % len(self.frames)]
        self.frame_index += 1
        elapsed = int(time.time() - self.started_at) if self.started_at else 0
        elapsed_text = "%02d:%02d" % (elapsed // 60, elapsed % 60)
        parts = ["⛫", frame, self.task_name]
        if self.phase:
            parts.extend(["|", self.phase])
        if self.note:
            parts.extend(["|", self.note])
        parts.extend(["|", elapsed_text])
        line = " ".join(parts)
        visible_line = line[: max(0, self._line_width() - 1)]
        padded_line = visible_line.ljust(self.last_rendered_length)
        self.stream.write("\r%s" % padded_line)
        self.last_rendered_length = len(visible_line)
        self.stream.flush()

    def _clear_line_locked(self):
        width = self._line_width()
        self.stream.write("\r%s\r" % (" " * width))
        self.stream.flush()
        self.last_rendered_length = 0

    def _line_width(self):
        return shutil.get_terminal_size(fallback=(120, 24)).columns


_reporter = StatusReporter()


def start_task(task_name):
    _reporter.start(task_name)
    _scan_events.emit("status", task_name)


def set_phase(phase):
    _reporter.set_phase(phase)
    if phase:
        _scan_events.emit("status", phase)


def stop():
    _reporter.stop()
    _scan_events.emit("status", "")


def print_message(message):
    _reporter.print_message(message)


def clear_line():
    _reporter.clear_line()


def set_note(note):
    _reporter.set_note(note)


def clear_note():
    _reporter.clear_note()


def is_enabled():
    return _reporter.is_enabled()
