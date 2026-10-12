import csv
import json
import os
import re
import uuid
from datetime import datetime
from urllib.parse import quote

import util.console as console
import util.error_logger as error_logger
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import choose_severity, make_finding, write_findings_to_disk


def _tls_below_12(value):
    m = re.search(r'(\d+(?:\.\d+)?)', str(value or ""))
    if not m:
        return False
    try:
        return float(m.group(1)) < 1.2
    except ValueError:
        return False


class Droplet:
    droplet_name = "Scan: Resource Review (All)"
    droplet_path = None
    droplet_type = "scan"
    output_folder_label = "resource_export"
    droplet_description = (
        "Exports detailed configuration data for common Azure resource types to\n"
        "CSV. Covers VMs, web apps, storage accounts, databases, Key Vaults,\n"
        "container registries, and more. Useful as a general-purpose resource\n"
        "inventory for review or audit.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    ARM_BASEURL = "https://management.azure.com"
    SUBSCRIPTIONS_API_VERSION = "2022-12-01"
    RESOURCES_API_VERSION = "2021-04-01"
    PROVIDERS_API_VERSION = "2021-04-01"
    EXPORTED_RESOURCE_TYPES = (
        "Microsoft.ContainerRegistry/registries",
        "Microsoft.Web/sites",
        "Microsoft.Compute/disks",
        "Microsoft.Compute/virtualMachines",
        "Microsoft.EventHub/namespaces",
        "Microsoft.KeyVault/vaults",
        "Microsoft.DBforPostgreSQL/servers",
        "Microsoft.DBforPostgreSQL/flexibleServers",
        "Microsoft.Cache/Redis",
        "Microsoft.ServiceBus/namespaces",
        "Microsoft.Sql/servers",
        "Microsoft.Storage/storageAccounts",
    )
    KNOWN_API_VERSIONS = {
        "Microsoft.Web/sites/config": ["2024-11-01", "2022-09-01"],
        "Microsoft.Compute/virtualMachines": ["2024-03-01", "2023-09-01"],
        "Microsoft.Compute/virtualMachines/extensions": ["2024-03-01", "2023-09-01"],
        "Microsoft.EventHub/namespaces/networkRuleSets": ["2024-01-01"],
        "Microsoft.ServiceBus/namespaces/networkRuleSets": ["2024-01-01"],
        "Microsoft.Sql/servers/firewallRules": ["2023-08-01"],
        "Microsoft.Sql/servers/virtualNetworkRules": ["2023-08-01"],
        "Microsoft.DBforPostgreSQL/flexibleServers/configurations": ["2021-06-01"],
        "Microsoft.DBforPostgreSQL/servers/firewallRules": ["2017-12-01"],
        "Microsoft.DBforPostgreSQL/servers/virtualNetworkRules": ["2017-12-01"],
        "Microsoft.Storage/storageAccounts/blobServices": ["2024-01-01"],
        "Microsoft.Storage/storageAccounts/blobServices/containers": ["2024-01-01"],
        "Microsoft.Storage/storageAccounts/fileServices/shares": ["2024-01-01"],
        "Microsoft.Storage/storageAccounts/queueServices/queues": ["2024-01-01"],
        "Microsoft.Storage/storageAccounts/tableServices/tables": ["2024-01-01"],
        "Microsoft.Network/privateEndpoints": ["2024-07-01"],
        "Microsoft.Network/networkInterfaces": ["2024-07-01"],
        "Microsoft.Network/publicIPAddresses": ["2024-07-01"],
        "Microsoft.Network/networkSecurityGroups": ["2024-07-01"],
        "Microsoft.Network/virtualNetworks/subnets": ["2024-07-01"],
    }
    ANY_ADDRESS_PREFIXES = {"*", "any", "0.0.0.0/0", "::/0", "internet"}
    ANY_PORT_MARKERS = {"*", "any", "0-65535", "1-65535"}
    ANY_PROTOCOLS = {"*", "any"}
    HIGH_RISK_VM_PORTS = {
        "22": "SSH",
        "3389": "RDP",
        "5985": "WinRM HTTP",
        "5986": "WinRM HTTPS",
    }

    # Each entry: (csv_column_name, bad_predicate, display_label, severity)
    # severity is "critical"/"high"/"medium"/"low" for an offending check, or
    # "info" for a good-state check that should never produce a finding/offender.
    # Add new checks here to extend coverage without changing any other code.
    METRICS_CONFIG = [
        {
            "label": "Storage Accounts",
            "file": "get_storageaccount_overview.csv",
            "checks": [
                ("Secure transfer", lambda v: v == "Disabled", "Secure transfer disabled (HTTP allowed)", "high"),
                ("Minimum TLS version", _tls_below_12, "TLS below 1.2", "medium"),
                ("Data-plane authorization", lambda v: v == "Shared Access Signatures (SAS)", "Using SAS authentication (not Azure AD)", "low"),
                ("Public access level", lambda v: v.startswith("Container:") or v.startswith("Blob within:"), "Public blob access enabled", "high"),
            ],
        },
        {
            "label": "App Services",
            "file": "get_appservice_overview.csv",
            "checks": [
                ("FTP State", lambda v: v == "FTP, FTPS", "Plaintext FTP enabled (FTP + FTPS)", "high"),
                ("FTP State", lambda v: v == "FTPS", "FTPS only enabled (encrypted FTP)", "info"),
                ("HTTPS only", lambda v: v == "No", "HTTPS not enforced", "high"),
                ("Minimum TLS version", _tls_below_12, "TLS below 1.2", "medium"),
            ],
        },
        {
            "label": "Virtual Machines",
            "file": "get_virtualmachine_overview.csv",
            "checks": [
                ("Risky inbound ports", lambda v: v != "None noted" and v != "", "Risky inbound ports open (SSH/RDP/WinRM)", "high"),
                ("Trusted launch", lambda v: v != "Enabled", "Without Trusted Launch", "low"),
                ("Password auth", lambda v: v == "Enabled", "Linux password auth enabled", "medium"),
            ],
        },
        {
            "label": "Key Vaults",
            "file": "get_keyvault_overview.csv",
            "checks": [
                ("Data-plane authorization", lambda v: v == "Vault access policies", "Using access policies (not RBAC)", "low"),
                ("Purge protection", lambda v: v == "Disabled", "Without purge protection", "medium"),
            ],
        },
        {
            "label": "SQL Servers",
            "file": "get_sqlserver_overview.csv",
            "checks": [
                ("Data-plane authorization", lambda v: v == "SQL credentials", "Using SQL credentials (not Azure AD)", "low"),
                ("Minimum TLS Version", _tls_below_12, "TLS below 1.2", "medium"),
            ],
        },
        {
            "label": "Container Registries (ACR)",
            "file": "get_acr_overview.csv",
            "checks": [
                ("Admin user", lambda v: v == "Enabled", "Admin user enabled", "medium"),
                ("Anonymous pull access", lambda v: v == "Enabled", "Anonymous pull enabled", "high"),
            ],
        },
        {
            "label": "Redis",
            "file": "get_redis_overview.csv",
            "checks": [
                ("Non-SSL port (6379)", lambda v: v == "Enabled", "Non-SSL port enabled", "medium"),
            ],
        },
        {
            "label": "Event Hubs",
            "file": "get_eventhub_overview.csv",
            "checks": [
                ("Data-plane authorization", lambda v: v != "Azure AD" and v != "", "Using SAS (not Azure AD)", "low"),
            ],
        },
        {
            "label": "Service Bus",
            "file": "get_servicebus_overview.csv",
            "checks": [
                ("Data-plane authorization", lambda v: v != "Azure AD" and v != "", "Using SAS (not Azure AD)", "low"),
            ],
        },
        {
            "label": "PostgreSQL",
            "file": "get_postgresql_overview.csv",
            "checks": [
                ("SSL enforcement", lambda v: v == "Disabled", "SSL not enforced", "high"),
                ("Minimum TLS version", _tls_below_12, "TLS below 1.2", "medium"),
            ],
        },
        {
            "label": "Managed Disks",
            "file": "get_disk_overview.csv",
            "checks": [
                ("Allow import/export from", lambda v: v == "All networks", "Public disk export/import allowed", "high"),
            ],
        },
    ]

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.api_version_cache = {}
        self.access_token = None
        self.resource_filters = None
        self._output_dir = None

    def _build_metrics_finding(self):
        if not self._output_dir or not os.path.isdir(self._output_dir):
            return None

        categories = []

        for config in self.METRICS_CONFIG:
            file_path = os.path.join(self._output_dir, config["file"])
            if not os.path.isfile(file_path):
                continue
            try:
                with open(file_path, newline="", encoding="utf-8") as fh:
                    rows = [r for r in csv.DictReader(fh) if (r.get("Name") or "").strip()]
            except Exception as exc:
                error_logger.log_current_exception(context="Could not read %s for security metrics" % file_path)
                console.warn("[!] Skipping metrics for unreadable CSV: %s (%s)" % (file_path, exc))
                continue
            if not rows:
                continue

            total = len(rows)
            checks = []
            for col, pred, label, severity in config["checks"]:
                bad = sum(1 for r in rows if pred(r.get(col, "") or ""))
                checks.append({"label": label, "bad": bad, "total": total, "info": severity == "info"})
            categories.append({"category": config["label"], "total": total, "checks": checks})

        if not categories:
            return None

        output_root = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(self.droplet_path))),
            "output",
        )
        # All CSVs in the output dir — include even those with no data rows
        all_csvs = sorted(
            os.path.join(self._output_dir, f)
            for f in os.listdir(self._output_dir)
            if f.endswith(".csv")
        )
        csv_paths = [
            os.path.relpath(fp, output_root).replace("\\", "/")
            for fp in all_csvs
        ]

        desc_lines = []
        for cat in categories:
            desc_lines.append("%s (%d total)" % (cat["category"], cat["total"]))
            for check in cat["checks"]:
                pct = round(check["bad"] / check["total"] * 100) if check["total"] else 0
                desc_lines.append("  %s: %d / %d (%d%%)" % (check["label"], check["bad"], check["total"], pct))
            desc_lines.append("")
        desc = "\n".join(desc_lines).rstrip()

        return {
            "id": str(uuid.uuid4()),
            "title": "Resource Configuration Security Metrics",
            "desc": desc,
            "severity": "info",
            "confidence": "high",
            "objects": [],
            "evidence": [],
            "rec": "Review highlighted metrics and address items where the percentage of non-compliant resources is high.",
            "meta": {
                "scan": self.droplet_name,
                "metrics": categories,
                "csv_paths": csv_paths,
            },
        }

    def _build_category_findings(self):
        if not self._output_dir or not os.path.isdir(self._output_dir):
            return []

        findings = []
        for config in self.METRICS_CONFIG:
            file_path = os.path.join(self._output_dir, config["file"])
            if not os.path.isfile(file_path):
                continue
            try:
                with open(file_path, newline="", encoding="utf-8") as fh:
                    rows = [r for r in csv.DictReader(fh) if (r.get("Name") or "").strip()]
            except Exception as exc:
                error_logger.log_current_exception(context="Could not read %s for category findings" % file_path)
                console.warn("[!] Skipping category finding for unreadable CSV: %s (%s)" % (file_path, exc))
                continue
            if not rows:
                continue

            total = len(rows)
            failing_checks = []
            paste_sections = []
            for col, pred, label, severity in config["checks"]:
                if severity == "info":
                    continue
                offenders = sorted({
                    r["Name"].strip()
                    for r in rows
                    if pred(r.get(col, "") or "")
                })
                if not offenders:
                    continue
                failing_checks.append({
                    "check": label,
                    "severity": severity,
                    "bad": len(offenders),
                    "total": total,
                    "offenders": offenders,
                })
                paste_sections.append("== %s ==\n%s" % (label, "\n".join(offenders)))

            if not failing_checks:
                continue

            severities = [check["severity"] for check in failing_checks]
            category_severity = choose_severity(severities, {s: s for s in severities}, default="low")
            distinct_offenders = sorted({name for check in failing_checks for name in check["offenders"]})

            findings.append(make_finding(
                title="%s — Configuration Issues" % config["label"],
                desc="%d %s reviewed. %d check%s failed across %d resource%s." % (
                    total,
                    config["label"].lower(),
                    len(failing_checks),
                    "" if len(failing_checks) == 1 else "s",
                    len(distinct_offenders),
                    "" if len(distinct_offenders) == 1 else "s",
                ),
                severity=category_severity,
                confidence="high",
                objects=[],
                evidence=failing_checks,
                rec="Review the listed checks and remediate the offending resources.",
                meta={
                    "scan": self.droplet_name,
                    "category": config["label"],
                    "paste_output": "\n\n".join(paste_sections),
                },
            ))

        return findings

    def run(self):
        status.set_phase("Authenticating with ARM")
        self.api_version_cache = {}
        self._output_dir = None
        self.access_token = tokenizer.get_arm_token()
        if not self.access_token:
            console.error("[!] Could not retrieve a valid ARM access token.")
            return []

        subscriptions = self.get_all_subscriptions()
        if not subscriptions:
            console.warn("[!] No subscriptions found.")
            return []

        jobs = self.get_export_jobs()

        total_jobs = len(jobs)
        for index, job in enumerate(jobs, start=1):
            status.set_phase("Export %s/%s: %s" % (index, total_jobs, job.__name__))
            try:
                job(subscriptions)
            except Exception as exc:
                error_logger.log_current_exception(context="Resource overview export failed: %s" % job.__name__)
                console.warn("[!] Export failed: %s" % job.__name__)
                console.warn("[!] Error: %s" % exc)

        status.set_phase("Building security metrics")
        metrics_finding = self._build_metrics_finding()
        findings = ([metrics_finding] if metrics_finding else []) + self._build_category_findings()
        if findings:
            write_findings_to_disk(findings, source_name=self.droplet_name)
        status.set_phase("Finished %s exports" % total_jobs)
        return findings

    def get_export_jobs(self):
        return [
            self.export_acr_overview,
            self.export_appservice_overview,
            self.export_disk_overview,
            self.export_virtualmachine_overview,
            self.export_eventhub_overview,
            self.export_keyvault_overview,
            self.export_postgresql_overview,
            self.export_redis_overview,
            self.export_servicebus_overview,
            self.export_sqlserver_overview,
            self.export_storageaccount_overview,
        ]

    def build_output_dir(self):
        if self._output_dir is None:
            tenant_id = tokenizer.get_current_tenant_id() or "unknown"
            epoch = int(datetime.now().timestamp())
            folder_name = "%s_%s" % (epoch, self.output_folder_label)
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(self.droplet_path)))
            self._output_dir = os.path.join(base_dir, "output", tenant_id, "csv", folder_name)
            os.makedirs(self._output_dir, exist_ok=True)
        return self._output_dir

    def build_output_file_path(self, scan_name):
        return os.path.join(self.build_output_dir(), "%s.csv" % scan_name)

    def set_resource_filters(self, resource_filters):
        normalized_filters = {}
        for subscription_id, resource_type_map in (resource_filters or {}).items():
            normalized_resource_type_map = {}
            for resource_type, resource_ids in (resource_type_map or {}).items():
                cleaned_resource_ids = sorted({resource_id for resource_id in (resource_ids or []) if resource_id})
                if cleaned_resource_ids:
                    normalized_resource_type_map[str(resource_type).lower()] = cleaned_resource_ids
            if normalized_resource_type_map:
                normalized_filters[str(subscription_id)] = normalized_resource_type_map
        self.resource_filters = normalized_filters or None

    def auth_headers(self):
        return {
            "Authorization": "Bearer %s" % self.access_token,
            "Content-Type": "application/json",
        }

    def arm_get(self, path_or_url):
        if str(path_or_url).startswith("https://"):
            url = path_or_url
        else:
            url = "%s%s" % (self.ARM_BASEURL, path_or_url)
        return http_client.get(url=url, headers=self.auth_headers())

    def arm_get_json(self, path_or_url):
        response = self.arm_get(path_or_url)
        try:
            return response.status_code, json.loads(response.content or b"{}")
        except ValueError:
            return response.status_code, {}

    def build_versioned_path(self, resource_path, api_version):
        separator = "&" if "?" in str(resource_path) else "?"
        return "%s%sapi-version=%s" % (resource_path, separator, api_version)

    def get_error_code(self, payload):
        return str(((payload.get("error") or {}).get("code")) or "").lower()

    def collect_paged_values_with_status(self, path_or_url):
        values = []
        next_url = path_or_url

        while next_url:
            status_code, payload = self.arm_get_json(next_url)
            if status_code != 200:
                return None, status_code, payload
            values.extend(payload.get("value", []))
            next_url = payload.get("nextLink") or payload.get("@odata.nextLink")

        return values, 200, {}

    def collect_paged_values(self, path_or_url):
        values, status_code, payload = self.collect_paged_values_with_status(path_or_url)
        return values

    def get_all_subscriptions(self):
        values = self.collect_paged_values("/subscriptions?api-version=%s" % self.SUBSCRIPTIONS_API_VERSION)
        if values is None:
            return []
        return [subscription.get("subscriptionId") for subscription in values if subscription.get("subscriptionId")]

    def get_all_resources_of_type_within_subscription(self, subscription_id, resource_type):
        query = "$filter=resourceType%%20eq%%20'%s'" % quote(resource_type, safe="/.")
        path = "/subscriptions/%s/resources?%s&api-version=%s" % (
            subscription_id,
            query,
            self.RESOURCES_API_VERSION,
        )
        values = self.collect_paged_values(path)
        if values is None:
            return None
        return [resource.get("id") for resource in values if resource.get("id")]

    def get_api_versions_for_resource_type(self, subscription_id, resource_type):
        cache_key = (subscription_id, resource_type.lower())
        if cache_key in self.api_version_cache:
            return self.api_version_cache[cache_key]

        resource_provider, resource_type_name = resource_type.split("/", 1)
        path = "/subscriptions/%s/providers/%s/resourceTypes?api-version=%s" % (
            subscription_id,
            resource_provider,
            self.PROVIDERS_API_VERSION,
        )
        values = self.collect_paged_values(path)
        if values is None:
            fallback_versions = self.KNOWN_API_VERSIONS.get(resource_type, [])
            self.api_version_cache[cache_key] = fallback_versions
            return fallback_versions

        for returned_resource_type in values:
            if str(returned_resource_type.get("resourceType", "")).lower() == resource_type_name.lower():
                versions = returned_resource_type.get("apiVersions", [])
                self.api_version_cache[cache_key] = versions
                return versions

        fallback_versions = self.KNOWN_API_VERSIONS.get(resource_type, [])
        self.api_version_cache[cache_key] = fallback_versions
        return fallback_versions

    def get_resource_content_using_multiple_api_versions(self, subscription_id, resource_path, resource_type):
        api_versions = self.get_api_versions_for_resource_type(subscription_id, resource_type)
        last_status_code = None
        last_payload = {}
        for api_version in api_versions:
            status_code, payload = self.arm_get_json(self.build_versioned_path(resource_path, api_version))
            if status_code == 200:
                return payload
            last_status_code = status_code
            last_payload = payload
            error_code = self.get_error_code(payload)
            if "featurenotsupported" in error_code:
                return None
        return None

    def get_resource_values_using_multiple_api_versions(self, subscription_id, resource_path, resource_type):
        api_versions = self.get_api_versions_for_resource_type(subscription_id, resource_type)
        last_status_code = None
        last_payload = {}
        for api_version in api_versions:
            values, status_code, payload = self.collect_paged_values_with_status(
                self.build_versioned_path(resource_path, api_version)
            )
            if status_code == 200:
                return values
            last_status_code = status_code
            last_payload = payload
            error_code = self.get_error_code(payload)
            if "featurenotsupported" in error_code:
                return None
        return None

    def get_subscription_resources(self, subscription_id, resource_type, had_errors):
        if self.resource_filters is not None:
            filtered_resources = (self.resource_filters.get(subscription_id) or {}).get(str(resource_type).lower())
            return list(filtered_resources) if filtered_resources is not None else []

        resources = self.get_all_resources_of_type_within_subscription(subscription_id, resource_type)
        if resources is None:
            had_errors["value"] = True
            return []
        return resources

    def fetch_resource_values(
        self,
        subscription_id,
        resource_path,
        resource_type,
        label,
        had_errors,
        optional=False,
    ):
        values = self.get_resource_values_using_multiple_api_versions(
            subscription_id,
            resource_path,
            resource_type,
        )
        if values is not None:
            return values
        if not optional:
            had_errors["value"] = True
        return None

    def append_csv_value(self, current_value, value_to_add):
        if not value_to_add:
            return current_value
        if not current_value:
            return value_to_add
        return "%s, %s" % (current_value, value_to_add)

    def format_tls_version(self, raw_value, source_prefix=None, default=""):
        if raw_value in (None, ""):
            return default
        version_text = str(raw_value)
        if source_prefix and source_prefix in version_text:
            version_text = version_text.split(source_prefix, 1)[1]
        version_text = version_text.replace("_", ".")
        return "TLS %s" % version_text

    def format_bool_status(self, value, enabled_label="Enabled", disabled_label="Disabled"):
        return enabled_label if bool(value) else disabled_label

    def format_days(self, properties):
        if properties.get("enabled"):
            return "%s days" % properties.get("days")
        return "Disabled"

    def is_enabled(self, value):
        if isinstance(value, dict):
            if "enabled" in value:
                return bool(value.get("enabled"))
            return bool(value)
        return bool(value)

    def is_public_network_enabled(self, value, allow_none=True):
        if value is None:
            return allow_none
        return str(value).strip().lower() == "enabled"

    def get_network_exposure(self, subscription_id, resource_properties, resource_path, label, had_errors):
        network_exposure = self.get_resource_network_exposure(subscription_id, resource_properties)
        if network_exposure.get("label") == "Unknown":
            had_errors["value"] = True
        return network_exposure

    def get_database_network_exposure(
        self,
        subscription_id,
        resource_properties,
        firewall_properties,
        vnet_properties,
        resource_path,
        label,
        had_errors,
    ):
        network_exposure = self.get_database_server_network_exposure(
            subscription_id,
            resource_properties,
            firewall_properties,
            vnet_properties,
        )
        if network_exposure.get("label") == "Unknown":
            had_errors["value"] = True
        return network_exposure

    def handle_resource_processing_error(self, label, resource_path, had_errors, exc):
        had_errors["value"] = True
        error_logger.log_current_exception(context="Resource overview item failed: %s %s" % (label, resource_path))
        console.warn("[!] Skipping %s: %s" % (label, resource_path))
        console.warn("[!] Error: %s" % exc)

    def extract_vnet_subnet_name(self, subnet_path):
        lowered_path = str(subnet_path or "").lower()
        start_string = "microsoft.network/virtualnetworks/"
        end_string = "/subnets/"
        if start_string not in lowered_path or end_string not in lowered_path:
            return None

        start_index = lowered_path.index(start_string) + len(start_string)
        end_index = lowered_path.index(end_string)
        vnet_name = lowered_path[start_index:end_index]
        subnet_name = lowered_path[end_index + len(end_string):]
        return "%s/%s" % (vnet_name, subnet_name)

    def get_resource_network_exposure(self, subscription_id, resource_properties):
        resource_network_exposure = {"whitelisted": [], "ispublic": True}
        had_resolution_error = False

        if "publicNetworkAccess" in resource_properties:
            public_access = resource_properties.get("publicNetworkAccess")
            has_public_network_access = self.is_public_network_enabled(public_access, allow_none=True)
            if not has_public_network_access:
                resource_network_exposure["ispublic"] = False

        if resource_network_exposure["ispublic"]:
            network_acls = None
            for acl_option in ("networkRuleSet", "networkAcls"):
                if acl_option in resource_properties:
                    network_acls = resource_properties[acl_option]
                    break

            if network_acls:
                network_rules = []
                default_action = str(network_acls.get("defaultAction", "Allow")).lower()

                if default_action == "deny":
                    resource_network_exposure["ispublic"] = False

                    for ip_rule in network_acls.get("ipRules", []):
                        for ip_rule_option in ("value", "ipMask"):
                            if ip_rule_option in ip_rule:
                                network_rules.append(ip_rule[ip_rule_option])
                                break

                    for vnet_rule in network_acls.get("virtualNetworkRules", []):
                        vnet_rule_path = vnet_rule.get("id") or ((vnet_rule.get("subnet") or {}).get("id"))
                        formatted = self.extract_vnet_subnet_name(vnet_rule_path)
                        if formatted:
                            network_rules.append(formatted)

                    bypassing_azure_services = ""
                    if "bypass" in network_acls:
                        bypassing_azure_services = network_acls["bypass"]
                    elif "networkRuleBypassOptions" in resource_properties:
                        bypassing_azure_services = resource_properties["networkRuleBypassOptions"]

                    if bypassing_azure_services and bypassing_azure_services != "None":
                        network_rules.append(bypassing_azure_services)

                    resource_network_exposure["whitelisted"].extend(network_rules)

        for private_endpoint_connection in resource_properties.get("privateEndpointConnections", []):
            private_endpoint_path = ((private_endpoint_connection.get("properties") or {}).get("privateEndpoint") or {}).get("id")
            if not private_endpoint_path:
                continue

            private_endpoint_content = self.get_resource_content_using_multiple_api_versions(
                subscription_id,
                private_endpoint_path,
                "Microsoft.Network/privateEndpoints",
            )
            if not private_endpoint_content:
                had_resolution_error = True
                continue

            private_endpoint_properties = private_endpoint_content.get("properties", {})
            subnet_label = self.extract_vnet_subnet_name((private_endpoint_properties.get("subnet") or {}).get("id"))
            private_endpoint_ip_addresses = []

            for dns_config in private_endpoint_properties.get("customDnsConfigs", []):
                private_endpoint_ip_addresses.extend(dns_config.get("ipAddresses", []))

            if not private_endpoint_ip_addresses:
                for network_interface in private_endpoint_properties.get("networkInterfaces", []):
                    network_interface_path = network_interface.get("id")
                    if not network_interface_path:
                        continue
                    network_interface_content = self.get_resource_content_using_multiple_api_versions(
                        subscription_id,
                        network_interface_path,
                        "Microsoft.Network/networkInterfaces",
                    )
                    if not network_interface_content:
                        had_resolution_error = True
                        continue
                    nic_properties = network_interface_content.get("properties", {})
                    for nic_ip_configuration in nic_properties.get("ipConfigurations", []):
                        nic_ip_address = (nic_ip_configuration.get("properties") or {}).get("privateIPAddress")
                        if nic_ip_address:
                            private_endpoint_ip_addresses.append(nic_ip_address)

            if subnet_label:
                resource_network_exposure["whitelisted"].append(
                    "%s (%s)" % (subnet_label, ", ".join(private_endpoint_ip_addresses))
                )

        if had_resolution_error:
            resource_network_exposure["label"] = "Unknown"

        return resource_network_exposure

    def get_database_server_network_exposure(
        self,
        subscription_id,
        resource_properties,
        firewall_properties,
        vnet_properties,
    ):
        db_server_network_exposure = {"whitelisted": [], "ispublic": True}
        firewall_rules = firewall_properties.get("value", [])
        vnet_rules = vnet_properties.get("value", [])
        has_public_network_access = True
        had_resolution_error = False

        if "publicNetworkAccess" in resource_properties:
            has_public_network_access = self.is_public_network_enabled(
                resource_properties["publicNetworkAccess"],
                allow_none=True,
            )
        elif "network" in resource_properties:
            has_public_network_access = self.is_public_network_enabled(
                (resource_properties.get("network") or {}).get("publicNetworkAccess"),
                allow_none=True,
            )

        if not has_public_network_access:
            db_server_network_exposure["ispublic"] = False

        if db_server_network_exposure["ispublic"]:
            for firewall_rule in firewall_rules:
                firewall_rule_properties = firewall_rule.get("properties", {})
                rule_start_ip = firewall_rule_properties.get("startIpAddress")
                rule_end_ip = firewall_rule_properties.get("endIpAddress")

                if rule_start_ip == rule_end_ip == "0.0.0.0":
                    if "Azure backbone" not in db_server_network_exposure["whitelisted"]:
                        db_server_network_exposure["whitelisted"].append("Azure backbone")
                elif rule_start_ip and rule_end_ip:
                    if rule_start_ip == rule_end_ip:
                        db_server_network_exposure["whitelisted"].append(rule_start_ip)
                    else:
                        db_server_network_exposure["whitelisted"].append("%s - %s" % (rule_start_ip, rule_end_ip))

            for vnet_rule in vnet_rules:
                vnet_rule_path = (vnet_rule.get("properties") or {}).get("virtualNetworkSubnetId")
                formatted = self.extract_vnet_subnet_name(vnet_rule_path)
                if formatted:
                    db_server_network_exposure["whitelisted"].append(formatted)

        for private_endpoint_connection in resource_properties.get("privateEndpointConnections", []):
            private_endpoint_path = ((private_endpoint_connection.get("properties") or {}).get("privateEndpoint") or {}).get("id")
            if not private_endpoint_path:
                continue

            private_endpoint_content = self.get_resource_content_using_multiple_api_versions(
                subscription_id,
                private_endpoint_path,
                "Microsoft.Network/privateEndpoints",
            )
            if not private_endpoint_content:
                had_resolution_error = True
                continue

            private_endpoint_properties = private_endpoint_content.get("properties", {})
            subnet_label = self.extract_vnet_subnet_name((private_endpoint_properties.get("subnet") or {}).get("id"))
            private_endpoint_ip_addresses = []

            for dns_config in private_endpoint_properties.get("customDnsConfigs", []):
                private_endpoint_ip_addresses.extend(dns_config.get("ipAddresses", []))

            if not private_endpoint_ip_addresses:
                for network_interface in private_endpoint_properties.get("networkInterfaces", []):
                    network_interface_content = self.get_resource_content_using_multiple_api_versions(
                        subscription_id,
                        network_interface.get("id"),
                        "Microsoft.Network/networkInterfaces",
                    )
                    if not network_interface_content:
                        had_resolution_error = True
                        continue
                    nic_properties = network_interface_content.get("properties", {})
                    for nic_ip_configuration in nic_properties.get("ipConfigurations", []):
                        private_ip_address = (nic_ip_configuration.get("properties") or {}).get("privateIPAddress")
                        if private_ip_address:
                            private_endpoint_ip_addresses.append(private_ip_address)

            if subnet_label:
                db_server_network_exposure["whitelisted"].append(
                    "%s (%s)" % (subnet_label, ", ".join(private_endpoint_ip_addresses))
                )

        if had_resolution_error:
            db_server_network_exposure["label"] = "Unknown"

        return db_server_network_exposure

    def export_resource_overview_to_csv(self, output_file_path, column_names, resource_overview):
        with open(output_file_path, "w", newline="", encoding="utf-8") as file_handle:
            writer = csv.writer(file_handle)
            writer.writerow(column_names)

            for resource_name in sorted(resource_overview):
                resource_properties = resource_overview[resource_name]
                row_payload = dict(resource_properties)
                if "network" in row_payload:
                    network_exposure = row_payload.pop("network")
                    whitelisted_locations = network_exposure["whitelisted"]
                    network_restriction_name = network_exposure.get("label") or (
                        "Selected networks" if whitelisted_locations
                        else "All networks" if network_exposure["ispublic"]
                        else "Private"
                    )
                    row_values = list(row_payload.values())
                    row_values.insert(0, network_restriction_name)
                    row_values.insert(0, resource_name)
                    writer.writerow(row_values)

                    if whitelisted_locations:
                        whitelisted_location_row = [""] * len(row_values)
                        for whitelisted_location in whitelisted_locations:
                            whitelisted_location_row[1] = whitelisted_location
                            writer.writerow(whitelisted_location_row)
                else:
                    row_values = list(row_payload.values())
                    row_values.insert(0, resource_name)
                    writer.writerow(row_values)

    def write_csv_and_report(self, scan_name, columns, rows, had_errors):
        output_file_path = self.build_output_file_path(scan_name)
        self.export_resource_overview_to_csv(output_file_path, columns, rows)
        console.debug("[↳] CSV exported: %s" % output_file_path)
        if had_errors:
            console.warn(
                "[!] %s: one or more resources could not be fully evaluated; results may be incomplete." % scan_name
            )

    def fetch_resource(self, subscription_id, resource_path, resource_type, label, had_errors):
        content = self.get_resource_content_using_multiple_api_versions(subscription_id, resource_path, resource_type)
        if content:
            return content
        had_errors["value"] = True
        return None

    def fetch_optional_resource(self, subscription_id, resource_path, resource_type):
        return self.get_resource_content_using_multiple_api_versions(subscription_id, resource_path, resource_type)

    def fetch_optional_resource_values(self, subscription_id, resource_path, resource_type):
        return self.get_resource_values_using_multiple_api_versions(subscription_id, resource_path, resource_type)

    def normalize_to_list(self, singular_value, plural_values):
        values = []
        if singular_value not in (None, ""):
            values.append(singular_value)
        values.extend(plural_values or [])
        return [value for value in values if value not in (None, "")]

    def get_resource_name_from_id(self, resource_id):
        if not resource_id:
            return ""
        return str(resource_id).rstrip("/").split("/")[-1]

    def get_parent_id(self, resource_id):
        parts = str(resource_id or "").strip("/").split("/")
        if len(parts) < 3:
            return None
        return "/" + "/".join(parts[:-2])

    def is_any_prefix(self, prefix):
        return str(prefix).strip().lower() in self.ANY_ADDRESS_PREFIXES

    def is_any_port(self, port_value):
        return str(port_value).strip().lower() in self.ANY_PORT_MARKERS

    def get_rule_source_prefixes(self, rule_properties):
        return self.normalize_to_list(
            rule_properties.get("sourceAddressPrefix"),
            rule_properties.get("sourceAddressPrefixes"),
        )

    def get_rule_destination_ports(self, rule_properties):
        return self.normalize_to_list(
            rule_properties.get("destinationPortRange"),
            rule_properties.get("destinationPortRanges"),
        )

    def get_sorted_inbound_rules(self, nsg_properties):
        rules = []
        for rule in (nsg_properties or {}).get("securityRules", []):
            rule_properties = rule.get("properties", {})
            if str(rule_properties.get("direction") or "").lower() != "inbound":
                continue
            rules.append(rule)
        return sorted(rules, key=lambda rule: (rule.get("properties") or {}).get("priority", 65535))

    def port_value_matches_candidate(self, port_value, candidate_port):
        normalized_port_value = str(port_value or "").strip()
        normalized_candidate = str(candidate_port or "").strip()

        if self.is_any_port(normalized_port_value):
            return True
        if normalized_candidate == "ANY":
            return self.is_any_port(normalized_port_value)
        if normalized_port_value == normalized_candidate:
            return True
        if "-" in normalized_port_value and normalized_candidate.isdigit():
            start, end = normalized_port_value.split("-", 1)
            if start.isdigit() and end.isdigit():
                return int(start) <= int(normalized_candidate) <= int(end)
        return False

    def rule_matches_source_token(self, rule_properties, source_token):
        source_prefixes = self.get_rule_source_prefixes(rule_properties)
        if not source_prefixes:
            # ASG-scoped rules apply only to their ASG's members, never to an
            # address-based source token like "ANY" (Internet) or a specific prefix.
            return not rule_properties.get("sourceApplicationSecurityGroups")
        if source_token == "ANY":
            return any(self.is_any_prefix(prefix) for prefix in source_prefixes)
        return any(
            self.is_any_prefix(prefix) or str(prefix).strip().lower() == str(source_token).strip().lower()
            for prefix in source_prefixes
        )

    def rule_matches_port_token(self, rule_properties, port_token):
        destination_ports = self.get_rule_destination_ports(rule_properties)
        if not destination_ports:
            return port_token == "ANY"
        return any(self.port_value_matches_candidate(port_value, port_token) for port_value in destination_ports)

    def evaluate_nsg_inbound_action(self, nsg_properties, source_token, port_token):
        for rule in self.get_sorted_inbound_rules(nsg_properties):
            rule_properties = rule.get("properties", {})
            if not self.rule_matches_source_token(rule_properties, source_token):
                continue
            if not self.rule_matches_port_token(rule_properties, port_token):
                continue
            return str(rule_properties.get("access") or "Deny").strip().lower()
        return "deny"

    def evaluate_effective_inbound_action(self, nsg_records, source_token, port_token):
        if not nsg_records:
            return "allow"
        for nsg_record in nsg_records:
            if not nsg_record:
                continue
            if self.evaluate_nsg_inbound_action(nsg_record["properties"], source_token, port_token) != "allow":
                return "deny"
        return "allow"

    def normalize_port_sort_key(self, port_value):
        text = str(port_value or "")
        if text == "ANY":
            return (0, 0, text)
        if text.isdigit():
            return (1, int(text), text)
        if "-" in text:
            start, _, end = text.partition("-")
            if start.isdigit() and end.isdigit():
                return (2, int(start), text)
        return (3, 0, text)

    def get_power_state(self, instance_view):
        for status_item in instance_view.get("statuses", []):
            status_code = str(status_item.get("code") or "")
            if status_code.startswith("PowerState/"):
                return status_code.split("/", 1)[1]
        return "Unknown"

    def format_vm_identity(self, identity):
        identity_type = str((identity or {}).get("type") or "")
        has_user_assigned = bool((identity or {}).get("userAssignedIdentities"))

        if not identity_type and not has_user_assigned:
            return "None"
        if identity_type.lower() == "systemassigned, userassigned":
            return "System + User assigned"
        if identity_type.lower() == "systemassigned":
            return "System assigned"
        if identity_type.lower() == "userassigned" or has_user_assigned:
            return "User assigned"
        return identity_type or "Unknown"

    def format_vm_password_auth(self, os_profile, os_type):
        linux_config = (os_profile or {}).get("linuxConfiguration") or {}
        windows_config = (os_profile or {}).get("windowsConfiguration") or {}

        if str(os_type).lower() == "linux":
            disable_password_auth = linux_config.get("disablePasswordAuthentication")
            if disable_password_auth is True:
                return "Disabled"
            if disable_password_auth is False:
                return "Enabled"
            return "Unknown"

        if str(os_type).lower() == "windows":
            return "Windows credentials"

        if windows_config:
            return "Windows credentials"
        if linux_config:
            return "Unknown"
        return "N/A"

    def format_vm_security_features(self, security_profile):
        if not security_profile:
            return "Unknown", "Unknown", "Unknown"

        uefi_settings = (security_profile or {}).get("uefiSettings") or {}
        security_type = (security_profile or {}).get("securityType")
        trusted_launch = (
            "Enabled" if str(security_type or "").lower() == "trustedlaunch"
            else "Disabled" if security_type
            else "Unknown"
        )
        secure_boot_enabled = uefi_settings.get("secureBootEnabled")
        vtpm_enabled = uefi_settings.get("vTpmEnabled")
        secure_boot = (
            self.format_bool_status(secure_boot_enabled, enabled_label="Enabled", disabled_label="Disabled")
            if secure_boot_enabled is not None
            else "Unknown"
        )
        vtpm = (
            self.format_bool_status(vtpm_enabled, enabled_label="Enabled", disabled_label="Disabled")
            if vtpm_enabled is not None
            else "Unknown"
        )
        return trusted_launch, secure_boot, vtpm

    def format_vm_boot_diagnostics(self, diagnostics_profile):
        boot_diagnostics = (diagnostics_profile or {}).get("bootDiagnostics") or {}
        if "enabled" not in boot_diagnostics:
            return "Unknown"
        return self.format_bool_status(boot_diagnostics.get("enabled"), enabled_label="Enabled", disabled_label="Disabled")

    def format_vm_disk_encryption(self, vm_properties):
        security_profile = vm_properties.get("securityProfile") or {}
        storage_profile = vm_properties.get("storageProfile") or {}
        os_disk = storage_profile.get("osDisk") or {}
        managed_disk = os_disk.get("managedDisk") or {}
        security_encryption_type = ((managed_disk.get("securityProfile") or {}).get("securityEncryptionType"))

        values = []
        if vm_properties.get("securityProfile", {}).get("encryptionAtHost"):
            values.append("Encryption at host")
        if managed_disk.get("diskEncryptionSet", {}).get("id"):
            values.append("CMK")
        if security_encryption_type:
            values.append(security_encryption_type)

        if values:
            return ", ".join(values)
        if os_disk:
            return "Platform-managed"
        return "Unknown"

    def format_vm_patch_mode(self, os_profile):
        windows_patch = ((os_profile or {}).get("windowsConfiguration") or {}).get("patchSettings") or {}
        linux_patch = ((os_profile or {}).get("linuxConfiguration") or {}).get("patchSettings") or {}

        patch_mode = windows_patch.get("patchMode") or linux_patch.get("patchMode")
        if patch_mode:
            return patch_mode

        if ((os_profile or {}).get("windowsConfiguration") or {}).get("enableAutomaticUpdates") is True:
            return "Automatic updates"
        return "Unknown"

    def format_vm_hotpatch(self, os_profile):
        windows_patch = ((os_profile or {}).get("windowsConfiguration") or {}).get("patchSettings") or {}
        hotpatch_enabled = windows_patch.get("enableHotpatching")
        if hotpatch_enabled is None:
            return "N/A"
        return self.format_bool_status(hotpatch_enabled, enabled_label="Enabled", disabled_label="Disabled")

    def build_nsg_lookup_record(self, subscription_id, nsg_id):
        nsg_content = self.fetch_optional_resource(subscription_id, nsg_id, "Microsoft.Network/networkSecurityGroups")
        if not nsg_content:
            return None
        return {
            "id": nsg_id,
            "name": nsg_content.get("name") or self.get_resource_name_from_id(nsg_id),
            "properties": nsg_content.get("properties", {}),
        }

    def collect_vm_network_context(self, subscription_id, vm_properties):
        context = {
            "network": {"whitelisted": [], "ispublic": False},
            "public_endpoints": [],
            "nsg_names": [],
            "inbound_summaries": [],
            "risky_ports": [],
        }
        nic_references = (vm_properties.get("networkProfile") or {}).get("networkInterfaces", [])
        path_contexts = []
        had_resolution_errors = False
        saw_public_ip_reference = False

        for nic_reference in nic_references:
            nic_id = nic_reference.get("id")
            if not nic_id:
                continue

            nic_content = self.fetch_optional_resource(subscription_id, nic_id, "Microsoft.Network/networkInterfaces")
            if not nic_content:
                had_resolution_errors = True
                continue

            nic_properties = nic_content.get("properties", {})
            nic_nsg_id = (nic_properties.get("networkSecurityGroup") or {}).get("id")
            nic_nsg_record = None
            nic_nsg_lookup_failed = False
            if nic_nsg_id:
                nic_nsg_record = self.build_nsg_lookup_record(subscription_id, nic_nsg_id)
                if nic_nsg_record:
                    context["nsg_names"].append(nic_nsg_record["name"])
                else:
                    had_resolution_errors = True
                    nic_nsg_lookup_failed = True

            for ip_configuration in nic_properties.get("ipConfigurations", []):
                ip_configuration_properties = ip_configuration.get("properties", {})
                path_context = {
                    "public_endpoints": [],
                    "nsg_records": [],
                    "source_candidates": set(),
                    "port_candidates": set(self.HIGH_RISK_VM_PORTS.keys()),
                    # An NSG that failed to resolve is silently absent from
                    # nsg_records, which would make evaluation treat this path
                    # as wide open by default. Track that so we report "Unknown"
                    # instead of confidently asserting exposure either way.
                    "incomplete": nic_nsg_lookup_failed,
                }
                if nic_nsg_record:
                    path_context["nsg_records"].append(nic_nsg_record)

                public_ip_id = (ip_configuration_properties.get("publicIPAddress") or {}).get("id")
                if public_ip_id:
                    saw_public_ip_reference = True
                    public_ip_content = self.fetch_optional_resource(
                        subscription_id,
                        public_ip_id,
                        "Microsoft.Network/publicIPAddresses",
                    )
                    if not public_ip_content:
                        had_resolution_errors = True
                    else:
                        public_ip_properties = public_ip_content.get("properties", {})
                        public_ip_address = public_ip_properties.get("ipAddress")
                        public_ip_fqdn = (public_ip_properties.get("dnsSettings") or {}).get("fqdn")
                        if public_ip_address:
                            path_context["public_endpoints"].append(public_ip_address)
                        if public_ip_fqdn:
                            path_context["public_endpoints"].append(public_ip_fqdn)

                subnet_id = (ip_configuration_properties.get("subnet") or {}).get("id")
                subnet_parent_id = self.get_parent_id(subnet_id)
                if subnet_id and subnet_parent_id:
                    subnet_content = self.fetch_optional_resource(
                        subscription_id,
                        subnet_id,
                        "Microsoft.Network/virtualNetworks/subnets",
                    )
                    if not subnet_content:
                        had_resolution_errors = True
                        path_context["incomplete"] = True
                    else:
                        subnet_nsg_id = ((subnet_content.get("properties") or {}).get("networkSecurityGroup") or {}).get("id")
                        if subnet_nsg_id:
                            subnet_nsg_record = self.build_nsg_lookup_record(subscription_id, subnet_nsg_id)
                            if subnet_nsg_record:
                                path_context["nsg_records"].append(subnet_nsg_record)
                                context["nsg_names"].append(subnet_nsg_record["name"])
                            else:
                                had_resolution_errors = True
                                path_context["incomplete"] = True

                if path_context["public_endpoints"]:
                    for nsg_record in path_context["nsg_records"]:
                        for rule in self.get_sorted_inbound_rules(nsg_record["properties"]):
                            rule_properties = rule.get("properties", {})
                            for source_prefix in self.get_rule_source_prefixes(rule_properties):
                                if not self.is_any_prefix(source_prefix):
                                    path_context["source_candidates"].add(source_prefix)
                            destination_ports = self.get_rule_destination_ports(rule_properties)
                            if destination_ports:
                                path_context["port_candidates"].update(str(port) for port in destination_ports)
                            else:
                                path_context["port_candidates"].add("ANY")
                    path_contexts.append(path_context)

        effective_specific_sources = set()
        internet_exposed = False
        had_incomplete_evaluation = False
        for path_context in path_contexts:
            context["public_endpoints"].extend(path_context["public_endpoints"])
            if path_context["incomplete"]:
                # An NSG on this path failed to resolve; evaluating it as-is
                # would treat the missing NSG as "no NSG attached" (wide open).
                # Skip asserting exposure from it and report "Unknown" instead.
                had_incomplete_evaluation = True
                continue
            port_candidates = sorted(path_context["port_candidates"], key=self.normalize_port_sort_key)
            nsg_records = path_context["nsg_records"]

            if self.evaluate_effective_inbound_action(nsg_records, "ANY", "ANY") == "allow":
                internet_exposed = True
                if "ANY from ANY" not in context["inbound_summaries"]:
                    context["inbound_summaries"].append("ANY from ANY")
                if "ANY" not in context["risky_ports"]:
                    context["risky_ports"].append("ANY")
                continue

            for port_candidate in port_candidates:
                if self.evaluate_effective_inbound_action(nsg_records, "ANY", port_candidate) == "allow":
                    internet_exposed = True
                    summary = "%s from ANY" % port_candidate
                    if summary not in context["inbound_summaries"]:
                        context["inbound_summaries"].append(summary)

            for risky_port, risky_label in self.HIGH_RISK_VM_PORTS.items():
                if self.evaluate_effective_inbound_action(nsg_records, "ANY", risky_port) == "allow":
                    risky_port_label = "%s (%s)" % (risky_port, risky_label)
                    if risky_port_label not in context["risky_ports"]:
                        context["risky_ports"].append(risky_port_label)

            if internet_exposed:
                continue

            for source_candidate in sorted(path_context["source_candidates"]):
                if self.evaluate_effective_inbound_action(nsg_records, source_candidate, "ANY") == "allow":
                    effective_specific_sources.add(source_candidate)
                    summary = "ANY from %s" % source_candidate
                    if summary not in context["inbound_summaries"]:
                        context["inbound_summaries"].append(summary)
                    continue

                for port_candidate in port_candidates:
                    if self.evaluate_effective_inbound_action(nsg_records, source_candidate, port_candidate) == "allow":
                        effective_specific_sources.add(source_candidate)
                        summary = "%s from %s" % (port_candidate, source_candidate)
                        if summary not in context["inbound_summaries"]:
                            context["inbound_summaries"].append(summary)
                        break

        if path_contexts:
            if internet_exposed:
                context["network"]["ispublic"] = True
                context["network"]["whitelisted"] = []
            elif effective_specific_sources:
                context["network"]["ispublic"] = True
                context["network"]["whitelisted"] = sorted(effective_specific_sources)
            elif had_incomplete_evaluation:
                context["network"]["label"] = "Unknown"
            else:
                context["network"]["ispublic"] = False
        elif saw_public_ip_reference and had_resolution_errors:
            context["network"]["label"] = "Unknown"
        elif had_resolution_errors and nic_references:
            context["network"]["label"] = "Unknown"

        if context["network"].get("label") == "Unknown" and not context["inbound_summaries"]:
            context["inbound_summaries"].append("Unknown - failed to resolve effective inbound path")

        context["public_endpoints"] = sorted(set(context["public_endpoints"]))
        context["nsg_names"] = sorted(set(context["nsg_names"]))
        context["inbound_summaries"] = context["inbound_summaries"][:5]
        context["had_resolution_errors"] = had_resolution_errors
        return context

    def export_acr_overview(self, subscriptions):
        resource_type = "Microsoft.ContainerRegistry/registries"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "ACR", had_errors)
                    if not content:
                        continue

                    properties = content.get("properties", {})
                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "ACR",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    policies = properties.get("policies", {})
                    trust_policy = (policies.get("trustPolicy") or {}).get("status", "")
                    rows[content["name"]] = {
                        "network": network_exposure,
                        "anonymouspull": "Enabled" if properties.get("anonymousPullEnabled") else "Disabled",
                        "trustpolicy": str(trust_policy).capitalize(),
                        "adminuser": "Enabled" if properties.get("adminUserEnabled") else "Disabled",
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("ACR", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_acr_overview",
            ["Name", "Allow access from", "Anonymous pull access", "Content trust", "Admin user"],
            rows,
            had_errors["value"],
        )

    def export_appservice_overview(self, subscriptions):
        resource_type = "Microsoft.Web/sites"
        config_resource_type = "Microsoft.Web/sites/config"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "App Service", had_errors)
                    if not content:
                        continue

                    app_service_properties = content.get("properties", {})
                    config_content = self.fetch_resource(
                        subscription,
                        "%s/config/web" % resource_path,
                        config_resource_type,
                        "App Service config",
                        had_errors,
                    )
                    if not config_content:
                        continue

                    config_properties = config_content.get("properties", {})
                    network_acls = {"defaultAction": "Allow"}
                    app_service_vnet_path = app_service_properties.get("virtualNetworkSubnetId")
                    network_acls["virtualNetworkRules"] = [{"id": app_service_vnet_path}] if app_service_vnet_path else []

                    ip_restrictions = config_properties.get("ipSecurityRestrictions", [])
                    is_network_restricted = any(
                        str(ip_restriction.get("action", "")).lower() == "deny"
                        and str(ip_restriction.get("ipAddress", "")).lower() == "any"
                        for ip_restriction in ip_restrictions
                    )
                    if is_network_restricted:
                        network_acls["defaultAction"] = "Deny"
                        network_acls["ipRules"] = [
                            {"value": ip_restriction.get("ipAddress")}
                            for ip_restriction in ip_restrictions
                            if str(ip_restriction.get("action", "")).lower() != "deny"
                        ]
                    else:
                        network_acls["ipRules"] = []

                    app_service_properties = dict(app_service_properties)
                    app_service_properties["networkAcls"] = network_acls
                    network_exposure = self.get_network_exposure(
                        subscription,
                        app_service_properties,
                        resource_path,
                        "App Service",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    kind = str(content.get("kind", "")).lower()
                    rows[content["name"]] = {
                        "network": network_exposure,
                        "type": "Function App" if "functionapp" in kind else "App Service",
                        "ftpstate": (
                            "FTP, FTPS"
                            if str(config_properties.get("ftpsState", "")).lower() == "allallowed"
                            else "FTPS"
                            if str(config_properties.get("ftpsState", "")).lower() == "ftpsonly"
                            else "Disabled"
                        ),
                        "httpsonly": "Yes" if app_service_properties.get("httpsOnly") else "No",
                        "tlsversion": self.format_tls_version(config_properties.get("minTlsVersion")),
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("App Service", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_appservice_overview",
            ["Name", "Allow access from", "Type", "FTP State", "HTTPS only", "Minimum TLS version"],
            rows,
            had_errors["value"],
        )

    def export_disk_overview(self, subscriptions):
        resource_type = "Microsoft.Compute/disks"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Disk", had_errors)
                    if not content:
                        continue
                    properties = content.get("properties", {})
                    # Azure defaults an unset networkAccessPolicy to "AllowAll".
                    policy = properties.get("networkAccessPolicy") or "AllowAll"
                    rows[content["name"]] = {
                        "networkaccesspolicy": (
                            "All networks" if policy == "AllowAll"
                            else "Private locations" if policy == "AllowPrivate"
                            else "Denied"
                        ),
                        "attachmentstate": properties.get("diskState"),
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Disk", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_disk_overview",
            ["Name", "Allow import/export from", "Attachment state"],
            rows,
            had_errors["value"],
        )

    def export_virtualmachine_overview(self, subscriptions):
        resource_type = "Microsoft.Compute/virtualMachines"
        extension_resource_type = "Microsoft.Compute/virtualMachines/extensions"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Virtual Machine", had_errors)
                    if not content:
                        continue

                    properties = content.get("properties", {})
                    hardware_profile = properties.get("hardwareProfile", {})
                    storage_profile = properties.get("storageProfile", {})
                    os_profile = properties.get("osProfile", {})
                    security_profile = properties.get("securityProfile", {})
                    diagnostics_profile = properties.get("diagnosticsProfile", {})
                    os_disk = storage_profile.get("osDisk", {})
                    os_type = os_disk.get("osType") or (
                        "Linux" if os_profile.get("linuxConfiguration")
                        else "Windows" if os_profile.get("windowsConfiguration")
                        else ""
                    )

                    instance_view = self.fetch_optional_resource(
                        subscription,
                        "%s/instanceView" % resource_path,
                        resource_type,
                    ) or {}
                    extensions = self.fetch_optional_resource_values(
                        subscription,
                        "%s/extensions" % resource_path,
                        extension_resource_type,
                    )
                    network_context = self.collect_vm_network_context(subscription, properties)
                    if network_context.get("had_resolution_errors"):
                        had_errors["value"] = True
                    extensions_label = (
                        "Unknown"
                        if extensions is None
                        else ", ".join(sorted(extension.get("name") for extension in extensions if extension.get("name"))) or "None detected"
                    )

                    trusted_launch, secure_boot, vtpm = self.format_vm_security_features(security_profile)
                    rows[content["name"]] = {
                        "network": network_context["network"],
                        "publicendpoints": ", ".join(network_context["public_endpoints"]) or "None",
                        "ostype": os_type or "Unknown",
                        "vmsize": hardware_profile.get("vmSize") or "Unknown",
                        "powerstate": self.get_power_state(instance_view),
                        "nics": str(len((properties.get("networkProfile") or {}).get("networkInterfaces", []))),
                        "nsgs": ", ".join(network_context["nsg_names"]) or "None",
                        "inboundsummary": "; ".join(network_context["inbound_summaries"][:3]) or (
                            "No inbound allow rules detected" if network_context["public_endpoints"] else "No public endpoint detected"
                        ),
                        "riskyports": ", ".join(network_context["risky_ports"]) or "None noted",
                        "identity": self.format_vm_identity(content.get("identity")),
                        "passwordauth": self.format_vm_password_auth(os_profile, os_type),
                        "trustedlaunch": trusted_launch,
                        "secureboot": secure_boot,
                        "vtpm": vtpm,
                        "bootdiagnostics": self.format_vm_boot_diagnostics(diagnostics_profile),
                        "diskencryption": self.format_vm_disk_encryption(properties),
                        "patchmode": self.format_vm_patch_mode(os_profile),
                        "hotpatch": self.format_vm_hotpatch(os_profile),
                        "extensions": extensions_label,
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Virtual Machine", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_virtualmachine_overview",
            [
                "Name",
                "Allow access from",
                "Public endpoints",
                "OS",
                "VM size",
                "Power state",
                "NICs",
                "Attached NSGs",
                "Inbound exposure summary",
                "Risky inbound ports",
                "Managed identity",
                "Password auth",
                "Trusted launch",
                "Secure Boot",
                "vTPM",
                "Boot diagnostics",
                "Disk encryption",
                "Patch mode",
                "Hotpatch",
                "Extensions",
            ],
            rows,
            had_errors["value"],
        )

    def export_eventhub_overview(self, subscriptions):
        resource_type = "Microsoft.EventHub/namespaces"
        network_rule_set_resource_type = "Microsoft.EventHub/namespaces/networkRuleSets"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Event Hub", had_errors)
                    rules_content = self.fetch_resource(
                        subscription,
                        "%s/networkRuleSets/default" % resource_path,
                        network_rule_set_resource_type,
                        "Event Hub network rules",
                        had_errors,
                    )
                    if not content or not rules_content:
                        continue

                    properties = content.get("properties", {})
                    network_rules_properties = dict(rules_content.get("properties", {}))
                    properties = dict(properties)
                    properties["publicNetworkAccess"] = network_rules_properties.pop("publicNetworkAccess", None)
                    properties["networkAcls"] = network_rules_properties
                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "Event Hub",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[content["name"]] = {
                        "network": network_exposure,
                        "tlsversion": self.format_tls_version(content.get("properties", {}).get("minimumTlsVersion")),
                        "authorization": "Azure AD" if content.get("properties", {}).get("disableLocalAuth") else "Shared Access Signature (SAS)",
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Event Hub", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_eventhub_overview",
            ["Name", "Allow access from", "Minimum TLS version", "Data-plane authorization"],
            rows,
            had_errors["value"],
        )

    def export_keyvault_overview(self, subscriptions):
        resource_type = "Microsoft.KeyVault/vaults"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Key Vault", had_errors)
                    if not content:
                        continue
                    properties = content.get("properties", {})
                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "Key Vault",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[content["name"]] = {
                        "network": network_exposure,
                        "authorization": "Azure AD" if properties.get("enableRbacAuthorization") else "Vault access policies",
                        "purge": self.format_bool_status(properties.get("enablePurgeProtection")),
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Key Vault", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_keyvault_overview",
            ["Name", "Allow access from", "Data-plane authorization", "Purge protection"],
            rows,
            had_errors["value"],
        )

    def export_postgresql_overview(self, subscriptions):
        base_resource_type = "Microsoft.DBforPostgreSQL"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resource_paths = []
            for resource_type in ("%s/servers" % base_resource_type, "%s/flexibleServers" % base_resource_type):
                resource_paths.extend(self.get_subscription_resources(subscription, resource_type, had_errors))

            for resource_path in resource_paths:
                try:
                    split_path = resource_path.rsplit("/", 3)
                    if len(split_path) < 4:
                        continue
                    resource_type = "%s/%s" % (split_path[1], split_path[2])
                    is_simple_server = split_path[2] == "servers"
                    content = self.fetch_resource(subscription, resource_path, resource_type, "PostgreSQL server", had_errors)
                    if not content:
                        continue

                    properties = content.get("properties", {})
                    ssl_enforcement = ""
                    minimum_tls_version = ""

                    if is_simple_server:
                        ssl_enforcement = properties.get("sslEnforcement")
                        minimum_tls_version = self.format_tls_version(
                            properties.get("minimalTlsVersion"),
                            source_prefix="TLS",
                        )
                    else:
                        configuration_resource_type = "%s/configurations" % resource_type
                        configurations_content = self.fetch_resource(
                            subscription,
                            "%s/configurations" % resource_path,
                            configuration_resource_type,
                            "PostgreSQL configurations",
                            had_errors,
                        )
                        if not configurations_content:
                            continue
                        for configuration in configurations_content.get("value", []):
                            configuration_name = configuration.get("name")
                            configuration_properties = configuration.get("properties", {})
                            if configuration_name == "require_secure_transport":
                                ssl_enforcement = "Enabled" if configuration_properties.get("value") == "on" else "Disabled"
                            elif configuration_name == "ssl_min_protocol_version":
                                minimum_tls_version = self.format_tls_version(
                                    configuration_properties.get("value"),
                                    source_prefix="TLSv",
                                )

                    firewall_resource_type = "%s/firewallRules" % resource_type
                    firewall_properties = self.fetch_resource(
                        subscription,
                        "%s/firewallRules" % resource_path,
                        firewall_resource_type,
                        "PostgreSQL firewall rules",
                        had_errors,
                    )
                    if not firewall_properties:
                        continue

                    if is_simple_server:
                        vnet_rule_resource_type = "%s/virtualNetworkRules" % resource_type
                        vnet_properties = self.fetch_resource(
                            subscription,
                            "%s/virtualNetworkRules" % resource_path,
                            vnet_rule_resource_type,
                            "PostgreSQL VNet rules",
                            had_errors,
                        )
                        if not vnet_properties:
                            continue
                    else:
                        network_properties = properties.get("network", {})
                        if str(network_properties.get("publicNetworkAccess", "")).lower() == "disabled":
                            vnet_properties = {
                                "value": [{"properties": {"virtualNetworkSubnetId": network_properties.get("delegatedSubnetResourceId")}}]
                            }
                        else:
                            vnet_properties = {"value": []}

                    network_exposure = self.get_database_network_exposure(
                        subscription,
                        properties,
                        firewall_properties,
                        vnet_properties,
                        resource_path,
                        "PostgreSQL server",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[content["name"]] = {
                        "network": network_exposure,
                        "sslenforcement": ssl_enforcement,
                        "tlsversion": minimum_tls_version,
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("PostgreSQL server", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_postgresql_overview",
            ["Name", "Allow access from", "SSL enforcement", "Minimum TLS version"],
            rows,
            had_errors["value"],
        )

    def export_redis_overview(self, subscriptions):
        resource_type = "Microsoft.Cache/Redis"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Redis database", had_errors)
                    if not content:
                        continue
                    properties = content.get("properties", {})
                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "Redis database",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[content["name"]] = {
                        "network": network_exposure,
                        "nonsslport": "Enabled" if properties.get("enableNonSslPort") else "Disabled",
                        "minimumtlsversion": (
                            "TLS 1.0 (unset)"
                            if "minimumTlsVersion" not in properties
                            else self.format_tls_version(properties.get("minimumTlsVersion"))
                        ),
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Redis database", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_redis_overview",
            ["Name", "Allow access from", "Non-SSL port (6379)", "Minimum TLS version for SSL port (6380)"],
            rows,
            had_errors["value"],
        )

    def export_servicebus_overview(self, subscriptions):
        resource_type = "Microsoft.ServiceBus/namespaces"
        network_rule_set_resource_type = "Microsoft.ServiceBus/namespaces/networkRuleSets"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Service Bus", had_errors)
                    rules_content = self.fetch_resource(
                        subscription,
                        "%s/networkRuleSets/default" % resource_path,
                        network_rule_set_resource_type,
                        "Service Bus network rules",
                        had_errors,
                    )
                    if not content or not rules_content:
                        continue

                    properties = dict(content.get("properties", {}))
                    network_rules_properties = dict(rules_content.get("properties", {}))
                    properties["publicNetworkAccess"] = network_rules_properties.pop("publicNetworkAccess", None)
                    properties["networkAcls"] = network_rules_properties
                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "Service Bus",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[content["name"]] = {
                        "network": network_exposure,
                        "authorization": "Azure AD" if content.get("properties", {}).get("disableLocalAuth") else "Shared Access Signatures (SAS)",
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Service Bus", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_servicebus_overview",
            ["Name", "Allow access from", "Data-plane authorization"],
            rows,
            had_errors["value"],
        )

    def export_sqlserver_overview(self, subscriptions):
        resource_type = "Microsoft.Sql/servers"
        firewall_rule_resource_type = "Microsoft.Sql/servers/firewallRules"
        vnet_rule_resource_type = "Microsoft.Sql/servers/virtualNetworkRules"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "SQL Server", had_errors)
                    if not content:
                        continue

                    properties = content.get("properties", {})
                    firewall_properties = self.fetch_resource(
                        subscription,
                        "%s/firewallRules" % resource_path,
                        firewall_rule_resource_type,
                        "SQL firewall rules",
                        had_errors,
                    )
                    vnet_properties = self.fetch_resource(
                        subscription,
                        "%s/virtualNetworkRules" % resource_path,
                        vnet_rule_resource_type,
                        "SQL VNet rules",
                        had_errors,
                    )
                    if not firewall_properties or not vnet_properties:
                        continue

                    network_exposure = self.get_database_network_exposure(
                        subscription,
                        properties,
                        firewall_properties,
                        vnet_properties,
                        resource_path,
                        "SQL Server",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    administrators = properties.get("administrators", {})
                    rows[content["name"]] = {
                        "network": network_exposure,
                        "tlsversion": (
                            self.format_tls_version(properties.get("minimalTlsVersion"))
                            if "minimalTlsVersion" in properties
                            else "TLS 1.0"
                        ),
                        "authorization": "Azure AD" if administrators.get("azureADOnlyAuthentication") else "SQL credentials",
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("SQL Server", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_sqlserver_overview",
            ["Name", "Allow access from", "Minimum TLS Version", "Data-plane authorization"],
            rows,
            had_errors["value"],
        )

    def export_storageaccount_overview(self, subscriptions):
        resource_type = "Microsoft.Storage/storageAccounts"
        rows = {}
        had_errors = {"value": False}

        for subscription in subscriptions:
            resources = self.get_subscription_resources(subscription, resource_type, had_errors)
            for resource_path in resources:
                try:
                    content = self.fetch_resource(subscription, resource_path, resource_type, "Storage Account", had_errors)
                    if not content:
                        continue

                    properties = content.get("properties", {})
                    storage_account_name = content.get("name")
                    secure_transfer = "Enabled" if properties.get("supportsHttpsTrafficOnly") else "Disabled"
                    minimum_tls_version = self.format_tls_version(
                        properties.get("minimumTlsVersion"),
                        source_prefix="TLS",
                    )

                    tags = list((content.get("tags") or {}).values())
                    purpose = "Cloud shell" if "azure-cloud-shell" in tags else ""
                    if re.compile(".*log.*").match(storage_account_name):
                        purpose = "Logging" if not purpose else "%s, Logging" % purpose

                    service_type = ""
                    containers_str = ""
                    public_access_level = ""
                    blob_versioning = ""
                    container_soft_delete = "Disabled"
                    blob_soft_delete = "Disabled"
                    immutability = "Disabled"
                    authorization = (
                        "Shared Access Signatures (SAS)"
                        if properties.get("allowSharedKeyAccess", True)
                        else "Azure AD"
                    )

                    containers = self.fetch_resource_values(
                        subscription,
                        "%s/blobServices/default/containers" % resource_path,
                        "%s/blobServices" % resource_type,
                        "Storage Account blob containers",
                        had_errors,
                        optional=True,
                    )
                    if containers is None:
                        had_errors["value"] = True
                    else:
                        all_containers = []
                        public_containers_and_blobs = {"containers": [], "blobs": []}
                        is_purpose_staticwebsite = False

                        blob_service_content = self.get_resource_content_using_multiple_api_versions(
                            subscription,
                            "%s/blobServices/default" % resource_path,
                            "%s/blobServices" % resource_type,
                        )
                        if not blob_service_content:
                            had_errors["value"] = True
                            continue

                        blob_service_properties = blob_service_content.get("properties", {})
                        container_soft_delete = self.format_days(
                            blob_service_properties.get("containerDeleteRetentionPolicy", {})
                        )
                        blob_soft_delete = self.format_days(
                            blob_service_properties.get("deleteRetentionPolicy", {})
                        )
                        blob_versioning = self.format_bool_status(
                            blob_service_properties.get("isVersioningEnabled")
                        )
                        immutability = self.format_bool_status(
                            self.is_enabled(properties.get("immutableStorageWithVersioning"))
                        )

                        for container in containers:
                            container_name = container.get("name")
                            container_properties = container.get("properties", {})
                            container_public_access = str(container_properties.get("publicAccess", "")).lower()
                            all_containers.append(container_name)

                            if properties.get("allowBlobPublicAccess", True):
                                if container_name == "$web" or container_public_access == "container":
                                    public_containers_and_blobs["containers"].append(container_name)
                                elif container_public_access == "blob":
                                    public_containers_and_blobs["blobs"].append(container_name)
                                else:
                                    public_access_level = "Private"
                            elif container_name == "$web":
                                public_containers_and_blobs["containers"].append(container_name)
                            else:
                                public_access_level = "Private"

                            is_purpose_staticwebsite = is_purpose_staticwebsite or container_name == "$web"

                        containers_str = ", ".join(all_containers)
                        if is_purpose_staticwebsite:
                            purpose = self.append_csv_value(purpose, "Static website")
                        if public_containers_and_blobs["containers"]:
                            public_access_level = "Container: %s" % ", ".join(public_containers_and_blobs["containers"])
                        if public_access_level and public_containers_and_blobs["blobs"]:
                            public_access_level = "%s ; Blob within: %s" % (
                                public_access_level,
                                ", ".join(public_containers_and_blobs["blobs"]),
                            )
                        elif not public_access_level and public_containers_and_blobs["blobs"]:
                            public_access_level = "Blob within: %s" % ", ".join(public_containers_and_blobs["blobs"])

                        service_type = self.append_csv_value(service_type, "Blob")

                    for service_suffix, service_label in (
                        ("fileServices/default/shares", "File"),
                        ("queueServices/default/queues", "Queue"),
                        ("tableServices/default/tables", "Table"),
                    ):
                        svc_parts = service_suffix.split("/")
                        service_resource_type = "%s/%s/%s" % (resource_type, svc_parts[0], svc_parts[2])
                        service_values = self.fetch_resource_values(
                            subscription,
                            "%s/%s" % (resource_path, service_suffix),
                            service_resource_type,
                            "Storage Account %s" % service_label,
                            had_errors,
                            optional=True,
                        )
                        if service_values:
                            service_type = self.append_csv_value(service_type, service_label)

                    network_exposure = self.get_network_exposure(
                        subscription,
                        properties,
                        resource_path,
                        "Storage Account",
                        had_errors,
                    )
                    if not network_exposure:
                        continue

                    rows[storage_account_name] = {
                        "network": network_exposure,
                        "securetransfer": secure_transfer,
                        "tlsversion": minimum_tls_version,
                        "servicetype": service_type,
                        "purpose": purpose,
                        "containers": containers_str,
                        "publicaccesslevel": public_access_level,
                        "blobversioning": blob_versioning,
                        "containersoftdelete": container_soft_delete,
                        "blobsoftdelete": blob_soft_delete,
                        "immutability": immutability,
                        "authorization": authorization,
                    }
                except Exception as exc:
                    self.handle_resource_processing_error("Storage Account", resource_path, had_errors, exc)

        self.write_csv_and_report(
            "get_storageaccount_overview",
            [
                "Name",
                "Allow access from",
                "Secure transfer",
                "Minimum TLS version",
                "Storage service in use",
                "Determined purpose",
                "Containers",
                "Public access level",
                "Blob versioning",
                "Container soft delete",
                "Blob soft delete",
                "Immutable",
                "Data-plane authorization",
            ],
            rows,
            had_errors["value"],
        )
