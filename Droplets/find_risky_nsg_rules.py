import json

import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, choose_severity, make_finding, make_object, write_findings_to_disk


class Droplet:
    droplet_name = "Scan: Find Risky NSG Inbound Rules"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Scans all Network Security Groups across every subscription for inbound\n"
        "rules permitting traffic from any source (0.0.0.0/0 or Internet) to\n"
        "sensitive or broad port ranges. Reports affected NICs and subnets.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    network_api_version = "2023-09-01"
    subscriptions_api_version = "2022-12-01"

    ANY_ADDRESS_PREFIXES = {"*", "any", "0.0.0.0/0", "::/0", "internet"}
    ANY_PORT_MARKERS = {"*", "any", "0-65535", "1-65535"}
    ANY_PROTOCOLS = {"*", "any"}

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []

    def arm_get(self, url):
        full_url = "https://management.azure.com%s" % url
        headers = {
            "Authorization": "Bearer %s" % tokenizer.get_arm_token(),
            "Content-Type": "application/json",
        }
        return http_client.get(url=full_url, headers=headers)

    def get_all_subscriptions(self):
        return self.arm_get("/subscriptions?api-version=%s" % self.subscriptions_api_version)

    def get_all_network_security_groups(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_network_interfaces(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/networkInterfaces?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def collect_values(self, response):
        json_res = json.loads(response.content or "{}")
        if "value" in json_res:
            return check_pagination(tokenizer.get_arm_token(), json_res, json_res["value"])
        return []

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

    def build_subnet_context(self, subnet_id):
        vnet_id = self.get_parent_id(subnet_id)
        return {
            "id": subnet_id,
            "name": self.get_resource_name_from_id(subnet_id),
            "virtual_network_id": vnet_id,
            "virtual_network_name": self.get_resource_name_from_id(vnet_id),
        }

    def is_any_prefix(self, prefix):
        return str(prefix).strip().lower() in self.ANY_ADDRESS_PREFIXES

    def is_any_port(self, port_value):
        return str(port_value).strip().lower() in self.ANY_PORT_MARKERS

    def is_broad_port_range(self, port_value):
        value = str(port_value).strip().lower()
        if self.is_any_port(value):
            return True
        if "-" not in value:
            return False
        start, end = value.split("-", 1)
        if not start.isdigit() or not end.isdigit():
            return False
        return int(start) <= 1 and int(end) >= 65535

    SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

    def classify_rule(self, rule):
        source_prefixes = self.normalize_to_list(
            rule.get("source_address_prefix"),
            rule.get("source_address_prefixes"),
        )
        destination_prefixes = self.normalize_to_list(
            rule.get("destination_address_prefix"),
            rule.get("destination_address_prefixes"),
        )
        destination_ports = self.normalize_to_list(
            rule.get("destination_port_range"),
            rule.get("destination_port_ranges"),
        )
        protocol = str(rule.get("protocol") or "").strip().lower()

        # A side scoped to an application security group has no address prefixes;
        # it is limited to the ASG's members, not open to any address.
        source_asgs = rule.get("source_application_security_groups") or []
        destination_asgs = rule.get("destination_application_security_groups") or []
        any_source = (not source_prefixes and not source_asgs) or any(
            self.is_any_prefix(prefix) for prefix in source_prefixes
        )
        any_destination = (not destination_prefixes and not destination_asgs) or any(
            self.is_any_prefix(prefix) for prefix in destination_prefixes
        )
        any_ports = not destination_ports or any(
            self.is_any_port(port) or self.is_broad_port_range(port)
            for port in destination_ports
        )
        any_protocol = protocol in self.ANY_PROTOCOLS

        if any_source and any_destination:
            severity = "high"
            summary = "Allows inbound from any source to any destination"
        elif any_source or any_destination or any_ports:
            severity = "medium"
            summary = "Allows broad inbound access with partial exposure"
        else:
            severity = "low"
            summary = "Allows inbound access but scope is constrained"

        return {
            "severity": severity,
            "summary": summary,
            "source_scope": "any" if any_source else "specific",
            "destination_scope": "any" if any_destination else "specific",
            "port_scope": "any" if any_ports else "specific",
            "protocol_scope": "any" if any_protocol else "specific",
        }

    def format_scope_list(self, prefixes, asg_ids):
        values = list(prefixes) + [
            "ASG:%s" % self.get_resource_name_from_id(asg_id) for asg_id in (asg_ids or [])
        ]
        text = ", ".join(values[:2])
        if len(values) > 2:
            text += "…"
        return text

    def format_rule_summary(self, rule, classification):
        ports = self.normalize_to_list(rule.get("destination_port_range"), rule.get("destination_port_ranges"))
        if classification["port_scope"] == "any":
            port_str = "ANY"
        else:
            port_str = ", ".join(str(p) for p in ports[:3])
            if len(ports) > 3:
                port_str += "…"

        if classification["source_scope"] == "any":
            src_str = "ANY"
        else:
            src_str = self.format_scope_list(
                self.normalize_to_list(rule.get("source_address_prefix"), rule.get("source_address_prefixes")),
                rule.get("source_application_security_groups"),
            )

        if classification["destination_scope"] == "any":
            dst_str = "ANY"
        else:
            dst_str = self.format_scope_list(
                self.normalize_to_list(rule.get("destination_address_prefix"), rule.get("destination_address_prefixes")),
                rule.get("destination_application_security_groups"),
            )

        return "%s from %s to %s" % (port_str, src_str, dst_str)

    def build_rule_record(self, rule):
        rule_props = rule.get("properties", {})
        return {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "priority": rule_props.get("priority"),
            "direction": rule_props.get("direction"),
            "access": rule_props.get("access"),
            "protocol": rule_props.get("protocol"),
            "source_port_range": rule_props.get("sourcePortRange"),
            "source_port_ranges": rule_props.get("sourcePortRanges", []),
            "destination_port_range": rule_props.get("destinationPortRange"),
            "destination_port_ranges": rule_props.get("destinationPortRanges", []),
            "source_address_prefix": rule_props.get("sourceAddressPrefix"),
            "source_address_prefixes": rule_props.get("sourceAddressPrefixes", []),
            "destination_address_prefix": rule_props.get("destinationAddressPrefix"),
            "destination_address_prefixes": rule_props.get("destinationAddressPrefixes", []),
            "source_application_security_groups": [
                group.get("id")
                for group in rule_props.get("sourceApplicationSecurityGroups", [])
                if group.get("id")
            ],
            "destination_application_security_groups": [
                group.get("id")
                for group in rule_props.get("destinationApplicationSecurityGroups", [])
                if group.get("id")
            ],
        }

    def build_nsg_finding(self, subscription, nsg, matched_rules):
        props = nsg.get("properties", {})
        classifications = [match["classification"] for match in matched_rules]
        severities = [classification["severity"] for classification in classifications]
        source_scopes = {classification["source_scope"] for classification in classifications}
        destination_scopes = {classification["destination_scope"] for classification in classifications}
        port_scopes = {classification["port_scope"] for classification in classifications}
        attached_subnets = matched_rules[0]["attached_subnets"]
        related_virtual_networks = matched_rules[0]["related_virtual_networks"]

        sorted_matches = sorted(
            matched_rules,
            key=lambda m: (
                self.SEVERITY_ORDER.get(m["classification"]["severity"], 3),
                m["rule"].get("priority") or 65535,
            ),
        )
        top_match = sorted_matches[0]
        top_rule_summary = self.format_rule_summary(top_match["rule"], top_match["classification"])
        top_rule_name = top_match["rule"].get("name") or "Rule"
        rule_suffix = " (+%d more)" % (len(matched_rules) - 1) if len(matched_rules) > 1 else ""
        desc = "%s: %s%s" % (top_rule_name, top_rule_summary, rule_suffix)

        nsg_object = make_object(
            "networkSecurityGroup",
            nsg.get("id"),
            nsg.get("name"),
            region=nsg.get("location"),
            subscription_name=subscription.get("displayName"),
        )
        subnet_objects = [
            make_object(
                "subnet",
                subnet.get("id"),
                subnet.get("name"),
                virtual_network_id=subnet.get("virtual_network_id"),
                virtual_network_name=subnet.get("virtual_network_name"),
            )
            for subnet in attached_subnets
        ]
        vnet_objects = [
            make_object("virtualNetwork", vnet.get("id"), vnet.get("name"))
            for vnet in related_virtual_networks
        ]
        nic_objects = [
            make_object("networkInterface", nic.get("id"), nic.get("id", "").split("/")[-1])
            for nic in props.get("networkInterfaces", [])
            if nic.get("id")
        ]

        return make_finding(
            title=nsg.get("name") or "NSG",
            desc=desc,
            severity=choose_severity(severities, {severity: severity for severity in severities}, default="low"),
            confidence="high",
            objects=[nsg_object] + vnet_objects + subnet_objects + nic_objects,
            evidence=[
                {
                    "subscription_name": subscription.get("displayName"),
                    "region": nsg.get("location"),
                    "attached_subnet_count": len(attached_subnets),
                    "attached_nic_count": len(props.get("networkInterfaces", [])),
                    "attached_subnets": attached_subnets,
                    "related_virtual_networks": related_virtual_networks,
                    "source_scopes": sorted(source_scopes),
                    "destination_scopes": sorted(destination_scopes),
                    "port_scopes": sorted(port_scopes),
                    "matched_rule_count": len(matched_rules),
                }
            ] + [
                {
                    "rule_name": match["rule"]["name"],
                    "rule_summary": self.format_rule_summary(match["rule"], match["classification"]),
                    "priority": match["rule"]["priority"],
                    "protocol": match["rule"]["protocol"],
                    "source_prefixes": self.normalize_to_list(
                        match["rule"].get("source_address_prefix"),
                        match["rule"].get("source_address_prefixes"),
                    ),
                    "destination_prefixes": self.normalize_to_list(
                        match["rule"].get("destination_address_prefix"),
                        match["rule"].get("destination_address_prefixes"),
                    ),
                    "destination_ports": self.normalize_to_list(
                        match["rule"].get("destination_port_range"),
                        match["rule"].get("destination_port_ranges"),
                    ),
                    "source_application_security_groups": match["rule"].get("source_application_security_groups"),
                    "destination_application_security_groups": match["rule"].get("destination_application_security_groups"),
                    "classification": match["classification"]["summary"],
                    "classification_severity": match["classification"]["severity"],
                    "source_scope": match["classification"]["source_scope"],
                    "destination_scope": match["classification"]["destination_scope"],
                    "port_scope": match["classification"]["port_scope"],
                    "protocol_scope": match["classification"]["protocol_scope"],
                }
                for match in sorted(matched_rules, key=lambda item: item["rule"].get("priority") or 65535)
            ],
            rec=(
                "Tighten inbound allow rules by constraining source prefixes, destination scope, "
                "protocols, and destination ports. Remove or narrow any broad any-to-any inbound rules."
            ),
            meta={
                "scan": self.droplet_name,
                "subscription_id": subscription.get("subscriptionId") or subscription.get("id"),
                "resource_id": nsg.get("id"),
                "related_virtual_network_count": len(related_virtual_networks),
                "attached_subnet_count": len(attached_subnets),
            },
        )

    def scan_network_security_group(self, subscription, nsg, nic_subnet_map):
        matched_rules = []
        props = nsg.get("properties", {})
        subnet_context_by_id = {}

        for subnet in props.get("subnets", []):
            subnet_id = subnet.get("id")
            if subnet_id:
                subnet_context_by_id[subnet_id] = self.build_subnet_context(subnet_id)

        for nic in props.get("networkInterfaces", []):
            for subnet_id in nic_subnet_map.get(nic.get("id"), []):
                subnet_context_by_id.setdefault(subnet_id, self.build_subnet_context(subnet_id))

        attached_subnets = sorted(subnet_context_by_id.values(), key=lambda item: item["id"])
        related_virtual_networks = sorted(
            {
                subnet["virtual_network_id"]: {
                    "id": subnet["virtual_network_id"],
                    "name": subnet["virtual_network_name"],
                }
                for subnet in attached_subnets
                if subnet.get("virtual_network_id")
            }.values(),
            key=lambda item: item["id"],
        )

        for rule in props.get("securityRules", []):
            normalized_rule = self.build_rule_record(rule)
            if str(normalized_rule.get("direction") or "").lower() != "inbound":
                continue
            if str(normalized_rule.get("access") or "").lower() != "allow":
                continue
            matched_rules.append(
                {
                    "rule": normalized_rule,
                    "classification": self.classify_rule(normalized_rule),
                    "attached_subnets": attached_subnets,
                    "related_virtual_networks": related_virtual_networks,
                }
            )

        if not matched_rules:
            return None

        return self.build_nsg_finding(subscription, nsg, matched_rules)

    def run(self):
        status.set_phase("Collecting subscriptions")
        subscriptions = self.collect_values(self.get_all_subscriptions())

        findings = []
        total_subscriptions = len(subscriptions)
        for index, subscription in enumerate(subscriptions, start=1):
            subscription_id = subscription.get("subscriptionId") or subscription.get("id")
            status.set_phase(
                "Subscription %s/%s: %s" % (
                    index,
                    total_subscriptions,
                    subscription.get("displayName"),
                )
            )
            nsgs = self.collect_values(self.get_all_network_security_groups(subscription_id))
            nics = self.collect_values(self.get_all_network_interfaces(subscription_id))
            console.debug("[↳] network security groups: %s" % len(nsgs))
            console.debug("[↳] network interfaces: %s" % len(nics))

            nic_subnet_map = {}
            for nic in nics:
                subnet_ids = []
                for ip_config in (nic.get("properties") or {}).get("ipConfigurations", []):
                    subnet_id = (((ip_config.get("properties") or {}).get("subnet")) or {}).get("id")
                    if subnet_id:
                        subnet_ids.append(subnet_id)
                if nic.get("id") and subnet_ids:
                    nic_subnet_map[nic.get("id")] = sorted(set(subnet_ids))

            for nsg in nsgs:
                finding = self.scan_network_security_group(subscription, nsg, nic_subnet_map)
                if finding:
                    findings.append(finding)

        status.set_phase("Writing %s NSG findings" % len(findings))
        self.findings = findings
        write_findings_to_disk(findings, source_name=self.droplet_name)
        return findings
