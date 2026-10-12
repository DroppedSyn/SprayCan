import os
import sys
import threading
import traceback
from datetime import datetime


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "content", "logs")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    return LOG_DIR


def build_log_path():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    return os.path.join(ensure_log_dir(), "%s.log" % timestamp)


def log_exception(exc_type, exc_value, exc_traceback, context=""):
    if exc_type is KeyboardInterrupt:
        return None

    log_path = build_log_path()
    formatted_trace = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write("timestamp: %s\n" % datetime.now().isoformat())
        if context:
            log_file.write("context: %s\n" % context)
        log_file.write("exception_type: %s\n" % getattr(exc_type, "__name__", str(exc_type)))
        log_file.write("exception: %s\n\n" % exc_value)
        log_file.write(formatted_trace)
    return log_path


def log_current_exception(context=""):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    if exc_type is None:
        return None
    return log_exception(exc_type, exc_value, exc_traceback, context=context)


def install_global_exception_logging():
    previous_excepthook = sys.excepthook

    def excepthook(exc_type, exc_value, exc_traceback):
        log_exception(exc_type, exc_value, exc_traceback, context="Unhandled exception")
        if previous_excepthook is not None:
            previous_excepthook(exc_type, exc_value, exc_traceback)

    sys.excepthook = excepthook

    if hasattr(threading, "excepthook"):
        previous_threading_excepthook = threading.excepthook

        def thread_excepthook(args):
            log_exception(
                args.exc_type,
                args.exc_value,
                args.exc_traceback,
                context="Unhandled thread exception in %s" % getattr(args.thread, "name", "unknown"),
            )
            if previous_threading_excepthook is not None:
                previous_threading_excepthook(args)

        threading.excepthook = thread_excepthook
