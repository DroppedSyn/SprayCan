import queue as _queue_module
import threading

_q: _queue_module.Queue = _queue_module.Queue(maxsize=2000)

# A cancelled scan's droplet keeps running in its worker thread (Python can't kill a thread
# mid-flight — see server.py's cancel endpoint), so it can keep calling emit() after a newer
# scan has already started. _current_generation marks which run's output is actually wanted;
# _thread_generation (set per-thread by the worker that's about to run a droplet) lets emit()
# silently drop output from a thread whose run has since been superseded, instead of letting
# stale log lines bleed into a later run's live output panel.
_current_generation = 0
_thread_generation = threading.local()


def set_current_generation(generation):
    global _current_generation
    _current_generation = generation


def set_thread_generation(generation):
    _thread_generation.value = generation


def clear():
    """Drain all buffered events — call this at the start of each scan."""
    while True:
        try:
            _q.get_nowait()
        except _queue_module.Empty:
            break


def emit(event_type: str, text: str):
    """Push an event onto the bus. Thread-safe. Terminal events (complete/error)
    are never dropped — they evict the oldest buffered event to make room."""
    my_generation = getattr(_thread_generation, "value", None)
    if my_generation is not None and my_generation != _current_generation:
        return  # from a droplet thread whose scan run has since been cancelled/superseded

    event = {"type": event_type, "text": text}
    try:
        _q.put_nowait(event)
    except _queue_module.Full:
        if event_type in ("complete", "error"):
            try:
                _q.get_nowait()
            except _queue_module.Empty:
                pass
            try:
                _q.put_nowait(event)
            except _queue_module.Full:
                pass


def get_nowait():
    """Remove and return the next event. Raises queue.Empty when the bus is empty."""
    return _q.get_nowait()
