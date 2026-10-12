# Single source of truth for the SprayCan version. Lives here (not in SprayCan.py) so droplets
# can import it: importing SprayCan.py would trigger its venv re-exec.
VERSION = "0.80"

PROJECT_URL = "https://github.com/DroppedSyn/SprayCan"

# Identifies SprayCan's own live HTTP traffic (e.g. the Front Door origin probe) in target logs.
USER_AGENT = "SprayCan/%s (+%s)" % (VERSION, PROJECT_URL)
