import os, importlib.util, json
from datetime import datetime, timezone

import util.console as console
import util.error_logger as error_logger
import util.status as status
import util.tokenizer as tokenizer
import util.http_client as http_client
from Objects.Finding import Finding
from util.paths import PROJECT_ROOT


class Core:
    dir_path = None
    graph_permissions_file = os.path.join(PROJECT_ROOT, "graph_permissions.json")


    def __init__(self, dir_path):
        self.dir_path = dir_path
        self.droplets = []
        self.get_droplets()

    def load_droplet_from_file(self, file_path):
        droplet_name = os.path.splitext(os.path.basename(file_path))[0]
        spec = importlib.util.spec_from_file_location(droplet_name, file_path)
        droplet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(droplet)
        return droplet

    def get_droplets(self):
        paths = [os.path.join(self.dir_path, f) for (self.dir_path, dirnames, filenames) in os.walk(self.dir_path)
                 for f in filenames]

        for p in paths:
            if p.endswith("py"):
                try:
                    module = self.load_droplet_from_file(p)
                except Exception as exc:
                    console.warn("[!] Skipping %s: %s" % (os.path.basename(p), exc))
                    continue
                if not hasattr(module, "Droplet"):
                    continue
                try:
                    self.droplets.append(module.Droplet(p))
                except Exception as exc:
                    console.warn("[!] Could not instantiate %s: %s" % (os.path.basename(p), exc))

    def should_manage_status(self, droplet):
        return getattr(droplet, "droplet_type", None) != "settings"

    def should_show_scan_completion_message(self, droplet):
        return getattr(droplet, "droplet_type", None) == "scan"

    def run_droplet(self, droplet, managed_status=None, swallow_exceptions=False, show_completion=True):
        droplet_name = getattr(droplet, "droplet_name", droplet.__class__.__name__)
        show_scan_completion_message = self.should_show_scan_completion_message(droplet)
        completed_successfully = False
        if managed_status is None:
            managed_status = self.should_manage_status(droplet)

        if managed_status:
            status.start_task(droplet_name)

        try:
            result = droplet.run()
            completed_successfully = True
            return result
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            log_path = error_logger.log_current_exception(context="Droplet failed: %s" % droplet_name)
            console.error("[!] Droplet failed: %s" % droplet_name)
            console.error("[!] Error: %s" % exc)
            if log_path:
                console.error("[!] Error log: %s" % os.path.relpath(log_path))
            if swallow_exceptions:
                return None
            raise
        finally:
            if managed_status:
                status.stop()
            if show_completion and completed_successfully:
                if show_scan_completion_message:
                    console.success("[✓] Scan complete: %s" % droplet_name)
                else:
                    console.success("[✓] Finished: %s" % droplet_name)


def make_object(kind, obj_id=None, name=None, **attrs):
    # Small, flexible object payload for finding relationships.
    obj = {
        "type": kind,
        "id": obj_id,
        "name": name,
    }
    # Allow droplets to attach scan-specific fields without changing the helper.
    obj.update(attrs)
    return obj


def make_finding(
    title,
    desc="",
    severity="info",
    confidence="medium",
    objects=None,
    evidence=None,
    rec="",
    meta=None,
):
    # Centralized finding construction keeps droplet code terse.
    return Finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence=confidence,
        objects=objects,
        evidence=evidence,
        rec=rec,
        meta=meta,
    )

def choose_severity(values, mapping, default="info"):
    # Return the highest severity present in a set of values.
    for severity in ("critical", "high", "medium", "low", "info"):
        for value in values:
            if mapping.get(value) == severity:
                return severity
    return default

def serialize_finding(finding):
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    if isinstance(finding, dict):
        return finding
    return finding.__dict__


def sanitize_filename(value):
    return "".join(char if char.isalnum() or char in ("-", "_") else "_" for char in value).strip("_")


def build_findings_filename(source_name=None):
    epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    scan_name = sanitize_filename(source_name or "findings")
    return "%s.%s.json" % (epoch_ms, scan_name)


def build_findings_payload(findings, source_name=None):
    return {
        "tenant_id": tokenizer.get_current_tenant_id(),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scan_name": source_name or "findings",
        "findings": [serialize_finding(finding) for finding in findings],
    }


def _tenant_output_dir():
    tenant_id = tokenizer.get_current_tenant_id() or "unknown"
    output_dir = os.path.join(PROJECT_ROOT, "output", tenant_id)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def write_findings_to_disk(findings, output_file=None, source_name=None):
    serialized_payload = build_findings_payload(findings, source_name=source_name)
    if output_file is None:
        output_file = os.path.join(_tenant_output_dir(), build_findings_filename(source_name=source_name))

    with open(output_file, "w") as file:
        json.dump(serialized_payload, file, indent=4)

    console.debug("[↳] Findings saved: %s" % output_file)
    return output_file


def write_json_payload_to_disk(json_payload, output_file=None, source_name=None):
    payload = dict(json_payload)
    payload.setdefault("tenant_id", tokenizer.get_current_tenant_id())
    payload.setdefault("generated_at_utc", datetime.now(timezone.utc).isoformat())
    payload.setdefault("scan_name", source_name or payload.get("scan_name") or "payload")
    if output_file is None:
        output_file = os.path.join(_tenant_output_dir(), build_findings_filename(source_name=source_name))

    with open(output_file, "w") as file:
        json.dump(payload, file, indent=4)

    console.debug("[↳] JSON payload saved: %s" % output_file)
    return output_file

def get_paginated_data(token, url):
    """
     Breakout Function for requesting the newly paginated data via the returned paginated URI.
    :param token: (access token)
    :param url:
    :return:
    """
    headers = {'Authorization': 'Bearer %s' % token,
               'Content-Type': 'application/json'}
    return http_client.get(url=url, headers=headers)

def check_pagination(token, json_res, data_objects):
    """
    Recursive funtion to check if more data is present, and then calls gathers said data via get_paginated_data
    :param token: (access token)
    :param data_objects:
    :param json_res:
    :param groups:
    :return:
    """

    # Microsoft Graph pages via '@odata.nextLink'; Azure Resource Manager (ARM) list
    # operations page via a plain 'nextLink' — no '@odata.' prefix. This helper is shared
    # by both Graph- and ARM-backed droplets, so it must check both keys or ARM responses
    # spanning more than one page get silently truncated to their first page.
    next_link = json_res.get('@odata.nextLink') or json_res.get('nextLink')
    if next_link:
        console.debug('[+] Found more data. Total objects %s' % len(data_objects))
        res = get_paginated_data(token, next_link)
        json_pagination_res = json.loads(res.content)
        data_objects += json_pagination_res.get('value', [])
        check_pagination(token, json_pagination_res, data_objects)
        return data_objects
    else:
        console.debug('[↳] Finished collecting data. Returning %s objects.' % len(data_objects))
        return data_objects

GRAPH_PERMISSIONS_MAX_AGE_DAYS = 30

def load_graph_permissions_from_disk():
    if not os.path.exists(Core.graph_permissions_file):
        console.info("[i] Graph permissions file not found — fetching from API.")
        persist_graph_permissions_to_disk()
    console.debug('[i] Loading Graph Permissions from disk.')
    with open(Core.graph_permissions_file) as graph_permissions_file:
        json_graph_permissions = json.load(graph_permissions_file)
    fetched_at_str = json_graph_permissions.get("_fetched_at")
    if fetched_at_str:
        try:
            fetched_at = datetime.fromisoformat(fetched_at_str)
            age_days = (datetime.now(timezone.utc) - fetched_at).days
            if age_days >= GRAPH_PERMISSIONS_MAX_AGE_DAYS:
                console.warn(
                    "[!] Graph permissions cache is %d days old. New permissions added by Microsoft may be missed. "
                    "Run refresh_graph_permissions to update." % age_days
                )
        except (ValueError, TypeError):
            pass
    return json_graph_permissions

def get_all_graph_permissions():
    """
    Attempts to grab role assignments for a group. This is fildering against the principalID of the group. (otherwise
    it's going to return every damn principal in the AD.)
    :param token:
    :param group:
    :return:
    """
    host = "graph.microsoft.com"
    url = "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=id,appId,displayName,appRoles,oauth2PermissionScopes,resourceSpecificApplicationPermissions"
    full_url = "https://%s%s" % (host, url)
    headers = {'Authorization': 'Bearer %s' % tokenizer.get_graph_token(),
               'Content-Type': 'application/json'}
    return http_client.get(url=full_url, headers=headers)

def persist_graph_permissions_to_disk():
    console.info("[i] Fetching new graph permissions.")
    res = get_all_graph_permissions()
    graph_permissions = json.loads(res.content)

    if 'value' in graph_permissions:
        graph_permissions = check_pagination(tokenizer.get_graph_token(), graph_permissions, graph_permissions['value'])

    write_to_disk(graph_permissions)

def write_to_disk(json_payload):
    if isinstance(json_payload, dict):
        json_payload["_fetched_at"] = datetime.now(timezone.utc).isoformat()
    with open(Core.graph_permissions_file, "w") as file:
        file.write(json.dumps(json_payload))
    console.debug("[↳] Graph permissions saved.")
