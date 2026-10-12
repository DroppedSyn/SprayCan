import util.scan_events as _scan_events
import util.settings as settings
import util.status as status


LEVEL_ORDER = {
    "debug": 10,
    "info": 20,
    "success": 20,
    "warn": 30,
    "error": 40,
}
VERBOSITY_THRESHOLD = {
    "debug": 10,
    "normal": 20,
    "quiet": 30,
}


def should_print(level):
    verbosity = settings.get_verbosity()
    threshold = VERBOSITY_THRESHOLD.get(verbosity, VERBOSITY_THRESHOLD["normal"])
    return LEVEL_ORDER[level] >= threshold


def emit(message, level="info"):
    if not should_print(level):
        return
    status.print_message(message)
    _scan_events.emit("line", message)


def debug(message):
    emit(message, level="debug")


def info(message):
    emit(message, level="info")


def success(message):
    emit(message, level="success")


def warn(message):
    emit(message, level="warn")


def error(message):
    emit(message, level="error")


def prompt(message):
    status.clear_line()
    return input(message)
