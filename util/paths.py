import os

# Repo root, anchored to this file's location rather than the process's cwd — headless/cron
# invocations of SprayCan.py aren't guaranteed to run from the repo root the way Canvas's
# server always does. Single source of truth; other modules import PROJECT_ROOT from here
# instead of each recomputing it independently.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
