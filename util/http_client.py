import json
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests

import util.console as console
import util.status as status


RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 10
DEFAULT_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BACKOFF_SECONDS = 30.0
LOW_ARM_BUDGET_THRESHOLD = 10

HOST_STATE = {}


def get_host_key(url):
    return (urlparse(url).netloc or "").lower()


def get_host_label(host):
    if host == "management.azure.com":
        return "arm"
    if host == "graph.microsoft.com":
        return "graph"
    return host or "unknown"


def get_host_state(host):
    if host not in HOST_STATE:
        HOST_STATE[host] = {
            "cooldown_until": 0.0,
            "arm_remaining": {},
        }
    return HOST_STATE[host]


def parse_arm_remaining_headers(headers):
    remaining = {}
    for header, value in headers.items():
        key = header.lower()
        if not key.startswith("x-ms-ratelimit-remaining-"):
            continue
        try:
            remaining[key] = int(value)
        except (TypeError, ValueError):
            continue
    return remaining


def min_arm_remaining(remaining_headers):
    if not remaining_headers:
        return None
    return min(remaining_headers.values())


def extract_request_id(headers):
    for header_name in ("request-id", "x-ms-request-id", "client-request-id"):
        if headers.get(header_name):
            return headers.get(header_name)
    return None


def maybe_wait_for_known_cooldown(host, url):
    state = get_host_state(host)
    now = time.time()
    if state["cooldown_until"] > now:
        delay = state["cooldown_until"] - now
        console.debug("[i] Waiting %.1fs for %s cooldown before request: %s" % (delay, get_host_label(host), url))
        time.sleep(delay)


def update_host_state_from_response(host, response):
    state = get_host_state(host)
    if host == "management.azure.com":
        state["arm_remaining"] = parse_arm_remaining_headers(response.headers)

    retry_after = parse_retry_after(response.headers.get("Retry-After"))
    if retry_after is not None and response.status_code in RETRY_STATUS_CODES:
        state["cooldown_until"] = max(state["cooldown_until"], time.time() + retry_after)


def maybe_wait_for_low_arm_budget(host, url):
    if host != "management.azure.com":
        return

    state = get_host_state(host)
    remaining = min_arm_remaining(state["arm_remaining"])
    if remaining is None or remaining > LOW_ARM_BUDGET_THRESHOLD:
        return

    delay = min(2.0, 0.2 * max(1, LOW_ARM_BUDGET_THRESHOLD - remaining + 1))
    console.debug("[i] ARM budget low (%s remaining). Backing off %.1fs before request: %s" % (remaining, delay, url))
    time.sleep(delay)


def parse_retry_after(value):
    if not value:
        return None

    try:
        seconds = float(value)
        return max(0.0, seconds)
    except (TypeError, ValueError):
        pass

    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def compute_backoff(attempt, retry_after=None):
    if retry_after is not None:
        return min(retry_after, DEFAULT_MAX_BACKOFF_SECONDS)

    base_delay = min(DEFAULT_BACKOFF_SECONDS * (2 ** attempt), DEFAULT_MAX_BACKOFF_SECONDS)
    return base_delay + random.uniform(0.0, 0.5)


def request(method, url, *, headers=None, max_retries=DEFAULT_MAX_RETRIES, timeout=DEFAULT_TIMEOUT, **kwargs):
    last_response = None
    host = get_host_key(url)

    for attempt in range(max_retries + 1):
        maybe_wait_for_known_cooldown(host, url)
        maybe_wait_for_low_arm_budget(host, url)

        try:
            response = requests.request(method=method, url=url, headers=headers, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            if attempt >= max_retries:
                status.clear_note()
                raise

            delay = compute_backoff(attempt)
            get_host_state(host)["cooldown_until"] = max(
                get_host_state(host)["cooldown_until"],
                time.time() + delay,
            )
            if status.is_enabled():
                status.set_note("↻ %s retry %s/%s (%.1fs)" % (get_host_label(host), attempt + 1, max_retries, delay))
            else:
                console.warn("[!] Request failed (%s). Retrying in %.1fs: %s" % (exc.__class__.__name__, delay, url))
            time.sleep(delay)
            continue

        last_response = response
        status.clear_note()
        update_host_state_from_response(host, response)
        if response.status_code not in RETRY_STATUS_CODES:
            return response

        if attempt >= max_retries:
            return response

        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        delay = compute_backoff(attempt, retry_after=retry_after)
        request_id = extract_request_id(response.headers)
        arm_remaining = min_arm_remaining(get_host_state(host)["arm_remaining"])
        extra = []
        if retry_after is not None:
            extra.append("retry-after=%ss" % int(retry_after))
        if arm_remaining is not None:
            extra.append("arm-remaining=%s" % arm_remaining)
        if request_id:
            extra.append("request-id=%s" % request_id)
        detail = " [%s]" % ", ".join(extra) if extra else ""
        console.warn("[!] HTTP %s from %s (%s). Retrying in %.1fs.%s" % (
            response.status_code,
            get_host_label(host),
            url,
            delay,
            detail,
        ))
        time.sleep(delay)

    return last_response


def get(url, *, headers=None, **kwargs):
    return request("GET", url, headers=headers, **kwargs)


def post(url, *, headers=None, **kwargs):
    return request("POST", url, headers=headers, **kwargs)


def get_json(url, *, headers=None, **kwargs):
    response = get(url, headers=headers, **kwargs)
    return json.loads(response.content)
