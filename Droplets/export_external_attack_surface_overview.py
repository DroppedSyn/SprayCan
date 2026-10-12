import csv
import json
import os
import re
import uuid

import util.console as console
import util.error_logger as error_logger
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Droplets.export_aztop_resource_overviews import Droplet as ResourceOverviewExporter
from Objects.Core import write_findings_to_disk


class Droplet(ResourceOverviewExporter):
    droplet_name = "Scan: External Resource Review"
    droplet_type = "scan"
    output_folder_label = "external_attack_surface_export"
    droplet_description = (
        "Exports all internet-facing Azure resources across subscriptions to CSV,\n"
        "including web apps, storage accounts, databases, Key Vaults, container\n"
        "registries, and AKS clusters. Flags resources with public endpoints and\n"
        "marks those needing manual network exposure review.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    RESOURCE_GRAPH_API_VERSION = "2021-03-01"
    EXTERNAL_ENDPOINT_RESOURCE_TYPES = (
        "microsoft.containerregistry/registries",
        "microsoft.web/sites",
        "microsoft.eventhub/namespaces",
        "microsoft.keyvault/vaults",
        "microsoft.dbforpostgresql/servers",
        "microsoft.dbforpostgresql/flexibleservers",
        "microsoft.cache/redis",
        "microsoft.servicebus/namespaces",
        "microsoft.sql/servers",
        "microsoft.storage/storageaccounts",
        "microsoft.containerservice/managedclusters",
        "microsoft.documentdb/databaseaccounts",
    )
    MANUAL_INVESTIGATION_PATTERN = re.compile(
        r".*(\.database\.(windows\.net|azure\.com|cosmos\.azure\.com)|\.azmk8s\.io)$",
        re.IGNORECASE,
    )
    REVIEWABLE_RESOURCE_TYPES = {resource_type.lower() for resource_type in ResourceOverviewExporter.EXPORTED_RESOURCE_TYPES}

    def __init__(self, droplet_path):
        super().__init__(droplet_path)

    def _build_metrics_finding(self):
        if not self._output_dir or not os.path.isdir(self._output_dir):
            return None

        inventory_path = os.path.join(self._output_dir, "inventory.csv")
        if not os.path.isfile(inventory_path):
            return None

        try:
            with open(inventory_path, newline="", encoding="utf-8") as fh:
                records = list(csv.DictReader(fh))
        except Exception:
            return None

        total = len(records)
        if not total:
            return None

        manual_count = sum(1 for r in records if r.get("Requires manual investigation", "") == "Yes")

        type_counts = {}
        for r in records:
            rt = r.get("Source resource type", "") or "Unknown"
            type_counts[rt] = type_counts.get(rt, 0) + 1

        categories = [
            {
                "category": "External Attack Surface",
                "total": total,
                "checks": [
                    {"label": "Requiring manual investigation", "bad": manual_count, "total": total},
                ],
            },
            {
                "category": "Exposed Resources by Type",
                "total": total,
                "checks": [
                    {"label": rt, "bad": count, "total": total}
                    for rt, count in sorted(type_counts.items(), key=lambda x: -x[1])
                ],
            },
        ]

        output_root = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(self.droplet_path))),
            "output",
        )
        csv_files = sorted(
            os.path.join(self._output_dir, f)
            for f in os.listdir(self._output_dir)
            if f.endswith(".csv")
        )
        csv_paths = [
            os.path.relpath(fp, output_root).replace("\\", "/")
            for fp in csv_files
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
            "title": "External Attack Surface Exposure Metrics",
            "desc": desc,
            "severity": "info",
            "confidence": "high",
            "objects": [],
            "evidence": [],
            "rec": "Investigate endpoints flagged for manual review and ensure all exposed resources have appropriate security controls in place.",
            "meta": {
                "scan": self.droplet_name,
                "metrics": categories,
                "csv_paths": csv_paths,
            },
        }

    def run(self):
        status.set_phase("Authenticating with ARM")
        self.api_version_cache = {}
        self._output_dir = None
        self.access_token = tokenizer.get_arm_token()
        self.set_resource_filters(None)
        if not self.access_token:
            console.error("[!] Could not retrieve a valid ARM access token.")
            return []

        subscriptions = self.get_all_subscriptions()
        if not subscriptions:
            console.warn("[!] No subscriptions found.")
            return []

        status.set_phase("Collecting endpoint-bound resources")
        endpoint_records = self.collect_endpoint_records(subscriptions)

        status.set_phase("Collecting public IP bindings")
        public_ip_records = self.collect_public_ip_records(subscriptions)

        inventory_records = endpoint_records + public_ip_records
        review_filters = self.build_review_filters(inventory_records)
        self.set_resource_filters(review_filters)
        self.write_inventory_csv(inventory_records)

        supported_resource_count = sum(len(resource_ids) for resource_ids_by_type in review_filters.values() for resource_ids in resource_ids_by_type.values())
        unsupported_count = sum(1 for record in inventory_records if not record["review_supported"])
        console.info(
            "[i] External attack surface inventory: %s records, %s reviewable resources, %s unsupported bindings."
            % (len(inventory_records), supported_resource_count, unsupported_count)
        )

        if supported_resource_count > 0:
            jobs = self.get_export_jobs()
            total_jobs = len(jobs)
            for index, job in enumerate(jobs, start=1):
                status.set_phase("External review %s/%s: %s" % (index, total_jobs, job.__name__))
                try:
                    job(subscriptions)
                except Exception as exc:
                    error_logger.log_current_exception(context="External attack surface export failed: %s" % job.__name__)
                    console.warn("[!] Export failed: %s" % job.__name__)
                    console.warn("[!] Error: %s" % exc)
        else:
            console.warn("[!] No reviewable externally bound resources were identified.")

        status.set_phase("Building exposure metrics")
        finding = self._build_metrics_finding()
        findings = [finding] if finding else []
        if findings:
            write_findings_to_disk(findings, source_name=self.droplet_name)
        status.set_phase("Finished external attack surface exports")
        return findings

    def resource_graph_headers(self):
        return self.auth_headers()

    def resource_graph_query(self, subscriptions, query):
        url = "%s/providers/Microsoft.ResourceGraph/resources?api-version=%s" % (
            self.ARM_BASEURL,
            self.RESOURCE_GRAPH_API_VERSION,
        )
        rows = []
        skip_token = None

        while True:
            request_body = {
                "subscriptions": subscriptions,
                "query": query,
                "options": {
                    "$top": 1000,
                    "resultFormat": "objectArray",
                },
            }
            if skip_token:
                request_body["options"]["$skipToken"] = skip_token

            response = http_client.post(url=url, headers=self.resource_graph_headers(), json=request_body)
            if response.status_code != 200:
                try:
                    payload = json.loads(response.content or b"{}")
                except ValueError:
                    payload = {}
                console.warn("[!] Resource Graph query failed with HTTP %s." % response.status_code)
                console.debug("[↳] Resource Graph error payload: %s" % payload)
                return []

            payload = json.loads(response.content or b"{}")
            rows.extend(payload.get("data", []))
            skip_token = payload.get("$skipToken") or payload.get("skipToken")
            if not skip_token:
                return rows

    def collect_endpoint_records(self, subscriptions):
        endpoint_type_list = ", ".join("'%s'" % resource_type for resource_type in self.EXTERNAL_ENDPOINT_RESOURCE_TYPES)
        query = """
Resources
| where type in~ (%s)
| where (
    properties contains 'fqdn'
    and (
        properties !contains 'apiServerAccessProfile'
        or tostring(properties['apiServerAccessProfile']['authorizedIPRanges']) == '[]'
    )
) or (
    properties['publicNetworkAccess'] == 'Enabled'
    and (
        (properties !contains 'networkAcls' and properties !contains 'networkRuleSet')
        or (
            tostring(properties['networkAcls']['ipRules']) == '[]'
            and tostring(properties['networkRuleSet']['ipRules']) == '[]'
        )
    )
) or (
    properties['networkAcls']['defaultAction'] == 'Allow'
    and tostring(properties['networkAcls']['ipRules']) == '[]'
) or (
    properties['networkRuleSet']['defaultAction'] == 'Allow'
    and tostring(properties['networkRuleSet']['ipRules']) == '[]'
)
| project subscriptionId, id, name, type,
    defaultHostName=tostring(properties['defaultHostName']),
    fqdn=tostring(properties['fqdn']),
    vaultUri=tostring(properties['vaultUri']),
    loginServer=tostring(properties['loginServer']),
    fullyQualifiedDomainName=tostring(properties['fullyQualifiedDomainName']),
    hostName=tostring(properties['hostName']),
    serviceBusEndpoint=tostring(properties['serviceBusEndpoint']),
    blobEndpoint=tostring(properties['primaryEndpoints']['blob']),
    fileEndpoint=tostring(properties['primaryEndpoints']['file']),
    queueEndpoint=tostring(properties['primaryEndpoints']['queue']),
    tableEndpoint=tostring(properties['primaryEndpoints']['table']),
    documentEndpoint=tostring(properties['documentEndpoint'])
| order by type asc, name asc
        """ % endpoint_type_list
        rows = self.resource_graph_query(subscriptions, query)
        records = []

        for row in rows:
            indicators = []
            for field_name in (
                "defaultHostName",
                "fqdn",
                "vaultUri",
                "loginServer",
                "fullyQualifiedDomainName",
                "hostName",
                "serviceBusEndpoint",
                "blobEndpoint",
                "fileEndpoint",
                "queueEndpoint",
                "tableEndpoint",
                "documentEndpoint",
            ):
                normalized_indicator = self.normalize_endpoint_indicator(row.get(field_name))
                if normalized_indicator and normalized_indicator not in indicators:
                    indicators.append(normalized_indicator)

            for indicator in indicators:
                review_resource_type = self.normalize_resource_type(row.get("type"))
                records.append(
                    self.build_inventory_record(
                        surface_kind="endpoint",
                        indicator=indicator,
                        source_resource_id=row.get("id"),
                        source_resource_type=row.get("type"),
                        review_resource_id=row.get("id"),
                        review_resource_type=review_resource_type,
                        note="Requires manual investigation" if self.is_manual_investigation_indicator(indicator) else "",
                    )
                )

        return records

    def collect_public_ip_records(self, subscriptions):
        query = """
Resources
| where type =~ 'microsoft.network/publicipaddresses' and isnotempty(properties['ipAddress'])
| project subscriptionId, id, name, type,
    publicIp=tostring(properties['ipAddress']),
    ipConfigurationId=tostring(properties['ipConfiguration']['id'])
| order by name asc
        """
        rows = self.resource_graph_query(subscriptions, query)
        records = []
        total_rows = len(rows)

        for index, row in enumerate(rows, start=1):
            status.set_phase("Resolving public IP bindings %s/%s" % (index, total_rows))
            review_resource_id, review_resource_type, note = self.resolve_public_ip_binding(
                row.get("subscriptionId"),
                row.get("id"),
                row.get("ipConfigurationId"),
            )
            records.append(
                self.build_inventory_record(
                    surface_kind="public_ip",
                    indicator=row.get("publicIp"),
                    source_resource_id=row.get("id"),
                    source_resource_type=row.get("type"),
                    review_resource_id=review_resource_id,
                    review_resource_type=review_resource_type,
                    note=note,
                )
            )

        return records

    def build_inventory_record(
        self,
        surface_kind,
        indicator,
        source_resource_id,
        source_resource_type,
        review_resource_id,
        review_resource_type,
        note="",
    ):
        normalized_review_type = self.normalize_resource_type(review_resource_type)
        return {
            "surface_kind": surface_kind,
            "indicator": indicator or "",
            "manual_investigation": "Yes" if self.is_manual_investigation_indicator(indicator) else "No",
            "source_resource_id": source_resource_id or "",
            "source_resource_type": self.normalize_resource_type(source_resource_type),
            "review_resource_id": review_resource_id or "",
            "review_resource_type": normalized_review_type,
            "review_supported": normalized_review_type in self.REVIEWABLE_RESOURCE_TYPES,
            "note": note or "",
        }

    def build_review_filters(self, inventory_records):
        review_filters = {}
        for record in inventory_records:
            if not record["review_supported"] or not record["review_resource_id"]:
                continue
            subscription_id = self.extract_subscription_id_from_resource_id(record["review_resource_id"])
            if not subscription_id:
                continue
            review_filters.setdefault(subscription_id, {}).setdefault(record["review_resource_type"], set()).add(
                record["review_resource_id"]
            )
        return review_filters

    def write_inventory_csv(self, inventory_records):
        output_file_path = self.build_output_file_path("inventory")
        with open(output_file_path, "w", newline="", encoding="utf-8") as file_handle:
            writer = csv.writer(file_handle)
            writer.writerow(
                [
                    "Surface kind",
                    "Indicator",
                    "Requires manual investigation",
                    "Source resource type",
                    "Source resource ID",
                    "Review resource type",
                    "Review resource ID",
                    "Review supported",
                    "Note",
                ]
            )
            for record in sorted(
                inventory_records,
                key=lambda item: (
                    item["surface_kind"],
                    item["indicator"].lower(),
                    item["review_resource_type"],
                    item["review_resource_id"].lower(),
                ),
            ):
                writer.writerow(
                    [
                        record["surface_kind"],
                        record["indicator"],
                        record["manual_investigation"],
                        record["source_resource_type"],
                        record["source_resource_id"],
                        record["review_resource_type"],
                        record["review_resource_id"],
                        "Yes" if record["review_supported"] else "No",
                        record["note"],
                    ]
                )
        console.debug("[↳] CSV exported: %s" % output_file_path)

    def resolve_public_ip_binding(self, subscription_id, public_ip_resource_id, ip_configuration_id):
        if not ip_configuration_id:
            return public_ip_resource_id, self.normalize_resource_type("Microsoft.Network/publicIPAddresses"), "Public IP is not currently attached."

        parent_resource_id = self.trim_child_resource_id(ip_configuration_id)
        parent_resource_type = self.extract_resource_type_from_resource_id(parent_resource_id)
        normalized_parent_resource_type = self.normalize_resource_type(parent_resource_type)

        if normalized_parent_resource_type == "microsoft.network/networkinterfaces":
            nic_content = self.get_resource_content_using_multiple_api_versions(
                subscription_id,
                parent_resource_id,
                "Microsoft.Network/networkInterfaces",
            )
            if nic_content:
                virtual_machine_id = ((nic_content.get("properties") or {}).get("virtualMachine") or {}).get("id")
                if virtual_machine_id:
                    return (
                        virtual_machine_id,
                        self.extract_resource_type_from_resource_id(virtual_machine_id),
                        "Public IP is attached through a NIC-backed virtual machine.",
                    )
            return parent_resource_id, parent_resource_type, "Public IP is attached through a network interface."

        return parent_resource_id, parent_resource_type, "Public IP is attached through an Azure network resource."

    def normalize_endpoint_indicator(self, value):
        cleaned_value = str(value or "").strip()
        if not cleaned_value:
            return ""
        for prefix in ("https://", "http://", "sb://"):
            if cleaned_value.lower().startswith(prefix):
                cleaned_value = cleaned_value[len(prefix):]
                break
        return cleaned_value.rstrip("/")

    def is_manual_investigation_indicator(self, indicator):
        return bool(self.MANUAL_INVESTIGATION_PATTERN.match(str(indicator or "").strip()))

    def trim_child_resource_id(self, resource_id):
        segments = [segment for segment in str(resource_id or "").strip("/").split("/") if segment]
        if len(segments) < 2:
            return resource_id
        return "/%s" % "/".join(segments[:-2])

    def extract_subscription_id_from_resource_id(self, resource_id):
        segments = [segment for segment in str(resource_id or "").strip("/").split("/") if segment]
        for index, segment in enumerate(segments):
            if segment.lower() == "subscriptions" and index + 1 < len(segments):
                return segments[index + 1]
        return ""

    def extract_resource_type_from_resource_id(self, resource_id):
        segments = [segment for segment in str(resource_id or "").strip("/").split("/") if segment]
        provider_index = None
        for index, segment in enumerate(segments):
            if segment.lower() == "providers":
                provider_index = index
                break
        if provider_index is None or provider_index + 1 >= len(segments):
            return ""

        provider_namespace = segments[provider_index + 1]
        type_segments = []
        for index in range(provider_index + 2, len(segments), 2):
            type_segments.append(segments[index])
        return "/".join([provider_namespace] + type_segments)

    def normalize_resource_type(self, resource_type):
        return str(resource_type or "").strip().lower()
