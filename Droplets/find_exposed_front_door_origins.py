import csv
import json
import os
import socket
from datetime import datetime

import requests

import util.console as console
import util.http_client as http_client
import util.settings as settings
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import make_finding, make_object, write_findings_to_disk
from util.paths import PROJECT_ROOT
from util.version import USER_AGENT


class Droplet:
    droplet_name = "Scan: Front Door Origin Exposure"
    droplet_type = "scan"
    droplet_path = None
    output_folder_label = "front_door_origin_exposure"
    droplet_description = (
        "Enumerates Azure Front Door (Standard/Premium) origins — App Service and\n"
        "API Management backends — and checks whether each can be reached directly,\n"
        "bypassing the Front Door WAF. Flags missing/weak x-azure-fdid enforcement,\n"
        "disabled or non-blocking WAF policies, and unrestricted SCM/Kudu endpoints.\n"
        "\n"
        "Always sends one lightweight, unretried GET per origin/slot/SCM host to\n"
        "confirm config-based verdicts against live reachability (no attack payload,\n"
        "identified via a distinct User-Agent). A second, optional live check — sending\n"
        "an XSS-style test string to the origin and its public domain to prove WAF\n"
        "bypass — is OFF by default (toggle: Settings > Front Door probe payload /\n"
        "the Scan page checkbox) since it doubles request volume and is far more\n"
        "likely to trip a WAF/IDS and get the scanning IP flagged or blocked.\n"
        "\n"
        "APIM verdicts use the global policy only — a header check present in an\n"
        "API/product-level policy but not the global one will read as EXPOSED here\n"
        "and needs manual confirmation. Classic Front Door (frontdoors) is flagged\n"
        "but not analyzed.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    ARM_BASEURL = "https://management.azure.com"
    SUBSCRIPTIONS_API_VERSION = "2022-12-01"
    RESOURCE_GRAPH_API_VERSION = "2021-03-01"
    CDN_API_VERSION = "2024-02-01"
    WEB_API_VERSION = "2023-12-01"
    APIM_API_VERSION = "2022-08-01"

    FD_SERVICE_TAG = "azurefrontdoor.backend"
    FDID_HEADER = "x-azure-fdid"

    PROBE_USER_AGENT = USER_AGENT
    PROBE_TIMEOUT_SECONDS = 8
    PROBE_PAYLOAD_PATH = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.access_token = None
        # The same App Service / APIM instance, or the same public domain, can be reached
        # through more than one origin group or Front Door profile (shared backends, primary +
        # failover routing). Without these, every such re-encounter redoes its ARM lookups and
        # live probes from scratch — on a tenant with a lot of origin overlap that's the
        # difference between hundreds and thousands of requests over the run.
        self._probe_cache = {}
        self._app_service_data_cache = {}
        self._apim_data_cache = {}
        self._dns_alias_cache = {}
        self._output_dir = None
        # Read once per run instead of on every origin/slot/SCM host: get_setting() takes a
        # lock and re-reads+re-parses settings.json from disk on every call, and this toggle
        # can't change mid-run.
        self._probe_payload_enabled = None

    # ------------------------------------------------------------------
    # ARM / Resource Graph plumbing
    # ------------------------------------------------------------------

    def auth_headers(self):
        return {
            "Authorization": "Bearer %s" % self.access_token,
            "Content-Type": "application/json",
        }

    def arm_get(self, path_or_url):
        url = path_or_url if str(path_or_url).startswith("https://") else "%s%s" % (self.ARM_BASEURL, path_or_url)
        return http_client.get(url=url, headers=self.auth_headers())

    def get_single(self, path_or_url):
        response = self.arm_get(path_or_url)
        try:
            payload = json.loads(response.content or b"{}")
        except ValueError:
            payload = {}
        return response.status_code, payload

    def collect_paged(self, path_or_url, label=None):
        # ARM list endpoints page via a plain 'nextLink' (no '@odata.' prefix, unlike Graph).
        values = []
        next_url = path_or_url
        while next_url:
            status_code, payload = self.get_single(next_url)
            if status_code != 200:
                if status_code != 404:
                    error = payload.get("error") or {}
                    console.warn(
                        "[!] ARM request failed with HTTP %s%s: %s"
                        % (status_code, " for %s" % label if label else "", error.get("message") or "Unknown ARM error")
                    )
                return values
            values.extend(payload.get("value", []))
            next_url = payload.get("nextLink") or payload.get("@odata.nextLink")
        return values

    def get_all_subscriptions(self):
        values = self.collect_paged(
            "/subscriptions?api-version=%s" % self.SUBSCRIPTIONS_API_VERSION, label="subscriptions"
        )
        return [subscription.get("subscriptionId") for subscription in values if subscription.get("subscriptionId")]

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
                "options": {"$top": 1000, "resultFormat": "objectArray"},
            }
            if skip_token:
                request_body["options"]["$skipToken"] = skip_token

            response = http_client.post(url=url, headers=self.auth_headers(), json=request_body)
            try:
                payload = json.loads(response.content or b"{}")
            except ValueError:
                payload = {}

            if response.status_code != 200:
                console.warn("[!] Resource Graph query failed with HTTP %s." % response.status_code)
                console.debug("[↳] Resource Graph error payload: %s" % payload)
                return rows

            rows.extend(payload.get("data", []))
            skip_token = payload.get("$skipToken") or payload.get("skipToken")
            if not skip_token:
                return rows

    # ------------------------------------------------------------------
    # Inventory (Resource Graph)
    # ------------------------------------------------------------------

    def get_front_door_profiles(self, subscriptions):
        query = """
resources
| where type =~ 'microsoft.cdn/profiles'
| where sku.name in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project id, name, subscriptionId, resourceGroup, sku = tostring(sku.name),
          frontDoorId = tostring(properties.frontDoorId)
        """
        return self.resource_graph_query(subscriptions, query)

    def get_classic_front_doors(self, subscriptions):
        query = """
resources
| where type =~ 'microsoft.network/frontdoors'
| project id, name, subscriptionId, resourceGroup, frontDoorId = tostring(properties.frontdoorId)
        """
        return self.resource_graph_query(subscriptions, query)

    def get_waf_policies(self, subscriptions):
        query = """
resources
| where type =~ 'microsoft.network/frontdoorwebapplicationfirewallpolicies'
| project id = tolower(id), name, subscriptionId, sku = tostring(sku.name),
          mode = tostring(properties.policySettings.mode),
          state = tostring(properties.policySettings.enabledState),
          managedRuleSets = properties.managedRules.managedRuleSets
        """
        return self.resource_graph_query(subscriptions, query)

    def get_app_services(self, subscriptions):
        query = """
resources
| where type =~ 'microsoft.web/sites'
| project id, name, subscriptionId, resourceGroup, kind,
          publicNetworkAccess = tostring(properties.publicNetworkAccess),
          defaultHostName = tostring(properties.defaultHostName),
          hostNames = properties.hostNames,
          enabledHostNames = properties.enabledHostNames
        """
        return self.resource_graph_query(subscriptions, query)

    def get_apim_services(self, subscriptions):
        query = """
resources
| where type =~ 'microsoft.apimanagement/service'
| project id, name, subscriptionId, resourceGroup, sku = tostring(sku.name),
          vnetType = tostring(properties.virtualNetworkType),
          publicNetworkAccess = tostring(properties.publicNetworkAccess),
          gatewayUrl = tostring(properties.gatewayUrl),
          hostnameConfigurations = properties.hostnameConfigurations,
          developerPortalUrl = tostring(properties.developerPortalUrl)
        """
        return self.resource_graph_query(subscriptions, query)

    # ------------------------------------------------------------------
    # Backend lookup tables
    # ------------------------------------------------------------------

    def build_app_service_lookup(self, app_services):
        lookup = {}
        for site in app_services:
            hostnames = set()
            default_host = site.get("defaultHostName")
            if default_host:
                hostnames.add(default_host.lower())
            for host in site.get("hostNames") or []:
                if host:
                    hostnames.add(host.lower())
            for host in site.get("enabledHostNames") or []:
                if host and "scm." not in host.lower():
                    hostnames.add(host.lower())
            for host in hostnames:
                lookup[host] = site
        return lookup

    def build_apim_lookup(self, apim_services):
        lookup = {}
        for apim in apim_services:
            gateway_url = apim.get("gatewayUrl") or ""
            if gateway_url:
                host = gateway_url.split("//")[-1].split("/")[0]
                if host:
                    lookup[host.lower()] = apim
            for hostname_config in apim.get("hostnameConfigurations") or []:
                host = hostname_config.get("hostName")
                if host:
                    lookup[host.lower()] = apim
        return lookup

    def resolve_aliases(self, host):
        # A shared backend can be routed to from more than one origin group/profile (the same
        # reason _probe_cache/_app_service_data_cache/_apim_data_cache exist), so cache the DNS
        # fallback too — otherwise every re-encounter of an origin that isn't a direct hostname
        # match redoes a live DNS resolution from scratch.
        if host in self._dns_alias_cache:
            return self._dns_alias_cache[host]
        try:
            # gethostbyname_ex returns the resolved canonical name separately (element 0) from
            # the alias list. The App Service / APIM hostname a custom-domain origin CNAMEs to
            # can surface as either the canonical name or an alias depending on how the resolver
            # collapses the chain, so match against both — dropping the canonical name silently
            # misclassifies such origins as Unknown/External and skips their exposure verdict.
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            aliases = ([canonical] if canonical else []) + (aliases or [])
        except OSError:
            aliases = []
        self._dns_alias_cache[host] = aliases
        return aliases

    def match_backend(self, origin_host, app_service_lookup, apim_lookup):
        host = (origin_host or "").lower().rstrip(".")
        if host in app_service_lookup:
            return "App Service", app_service_lookup[host]
        if host in apim_lookup:
            return "API Management", apim_lookup[host]

        aliases = self.resolve_aliases(host)
        for alias in aliases:
            alias = alias.lower().rstrip(".")
            if alias in app_service_lookup:
                return "App Service", app_service_lookup[alias]
            if alias in apim_lookup:
                return "API Management", apim_lookup[alias]

        return "Unknown/External", None

    # ------------------------------------------------------------------
    # Front Door topology (per profile)
    # ------------------------------------------------------------------

    def collect_profile_topology(self, profile_id):
        endpoints = self.collect_paged(
            "%s/afdEndpoints?api-version=%s" % (profile_id, self.CDN_API_VERSION), label="afdEndpoints"
        )
        origin_groups = self.collect_paged(
            "%s/originGroups?api-version=%s" % (profile_id, self.CDN_API_VERSION), label="originGroups"
        )
        custom_domains = self.collect_paged(
            "%s/customDomains?api-version=%s" % (profile_id, self.CDN_API_VERSION), label="customDomains"
        )
        security_policies = self.collect_paged(
            "%s/securityPolicies?api-version=%s" % (profile_id, self.CDN_API_VERSION), label="securityPolicies"
        )

        origins_by_group = {}
        for group in origin_groups:
            group_id = group.get("id")
            if not group_id:
                continue
            origins_by_group[group_id] = self.collect_paged(
                "%s/origins?api-version=%s" % (group_id, self.CDN_API_VERSION), label="origins"
            )

        routes_by_endpoint = {}
        for endpoint in endpoints:
            endpoint_id = endpoint.get("id")
            if not endpoint_id:
                continue
            routes_by_endpoint[endpoint_id] = self.collect_paged(
                "%s/routes?api-version=%s" % (endpoint_id, self.CDN_API_VERSION), label="routes"
            )

        return {
            "endpoints": endpoints,
            "origin_groups": origin_groups,
            "origins_by_group": origins_by_group,
            "custom_domains": custom_domains,
            "security_policies": security_policies,
            "routes_by_endpoint": routes_by_endpoint,
        }

    def build_domain_lookup(self, topology):
        # A route with no explicit custom domain still routes through the endpoint's own
        # default *.azurefd.net hostname, so that hostname is modeled as a synthetic domain
        # keyed by the endpoint id.
        domains = {}
        for domain in topology["custom_domains"]:
            domain_id = (domain.get("id") or "").lower()
            hostname = (domain.get("properties") or {}).get("hostName") or domain.get("hostName")
            if domain_id and hostname:
                domains[domain_id] = hostname
        for endpoint in topology["endpoints"]:
            endpoint_id = (endpoint.get("id") or "").lower()
            hostname = (endpoint.get("properties") or {}).get("hostName") or endpoint.get("hostName")
            if endpoint_id and hostname:
                domains["endpoint:%s" % endpoint_id] = hostname
        return domains

    def normalize_domain_ref(self, domain_id):
        # ARM resource ids are case-insensitive and cross-references (route -> customDomains,
        # securityPolicy -> associations) often differ in casing from the listed resource's own
        # id, so every id used as a lookup key is lowercased. A security policy association on
        # an endpoint's default *.azurefd.net domain references the afdEndpoints resource
        # itself, which build_domain_lookup keys as "endpoint:<id>".
        domain_id = (domain_id or "").lower()
        if "/afdendpoints/" in domain_id:
            return "endpoint:%s" % domain_id
        return domain_id

    def build_domain_waf_lookup(self, topology, waf_policy_lookup):
        domain_waf = {}
        for policy in topology["security_policies"]:
            params = ((policy.get("properties") or {}).get("parameters")) or {}
            waf_policy_id = (params.get("wafPolicy") or {}).get("id")
            if not waf_policy_id:
                continue
            waf_policy_id = waf_policy_id.lower()
            for association in params.get("associations") or []:
                for domain_ref in association.get("domains") or []:
                    domain_id = self.normalize_domain_ref(domain_ref.get("id"))
                    if domain_id:
                        domain_waf[domain_id] = waf_policy_id
        return domain_waf

    def build_origin_reach_map(self, topology, domain_lookup, domain_waf_lookup):
        # origin_group_id -> {"domains": [(hostname, waf_policy_id_or_None), ...], "active": bool}
        reach = {}
        for endpoint in topology["endpoints"]:
            endpoint_id = endpoint.get("id")
            for route in topology["routes_by_endpoint"].get(endpoint_id, []):
                route_props = route.get("properties") or route
                origin_group_id = ((route_props.get("originGroup") or {}).get("id") or "").lower()
                if not origin_group_id:
                    continue
                route_enabled = (route_props.get("enabledState") or "Enabled") != "Disabled"
                custom_domain_refs = route_props.get("customDomains") or []
                domain_ids = [self.normalize_domain_ref(ref.get("id")) for ref in custom_domain_refs if ref.get("id")]
                if not domain_ids:
                    domain_ids = ["endpoint:%s" % (endpoint_id or "").lower()]

                entry = reach.setdefault(origin_group_id, {"domains": [], "active": False})
                entry["active"] = entry["active"] or route_enabled
                for domain_id in domain_ids:
                    hostname = domain_lookup.get(domain_id)
                    if not hostname:
                        continue
                    waf_policy_id = domain_waf_lookup.get(domain_id)
                    pair = (hostname, waf_policy_id)
                    if pair not in entry["domains"]:
                        entry["domains"].append(pair)
        return reach

    # ------------------------------------------------------------------
    # Verdict logic
    # ------------------------------------------------------------------

    def effective_default_action(self, rules, default_action):
        if default_action:
            return default_action
        # Legacy: no explicit default. Empty list => Azure injects "Allow all".
        # Any explicit non-"Any" Allow rule => implicit deny for unmatched traffic.
        real_allows = [r for r in (rules or []) if r.get("action") == "Allow" and r.get("ipAddress") != "Any"]
        return "Deny" if real_allows else "Allow"

    def has_allow_all_rule(self, rules):
        return any(r.get("action") == "Allow" and r.get("ipAddress") == "Any" for r in (rules or []))

    def is_front_door_service_tag_rule(self, rule):
        if rule.get("action") != "Allow" or (rule.get("tag") or "").lower() != "servicetag":
            return False
        return (rule.get("ipAddress") or "").strip().lower() == self.FD_SERVICE_TAG

    def rule_matches_fdid(self, rule, fdid):
        if not fdid:
            return False
        headers = rule.get("headers") or {}
        for header_name, header_values in headers.items():
            if header_name.lower() != self.FDID_HEADER:
                continue
            for value in header_values or []:
                if (value or "").strip().lower() == fdid.strip().lower():
                    return True
        return False

    def compute_app_service_verdict(self, config, fdid, public_network_access, has_approved_private_endpoint):
        if public_network_access == "Disabled" and has_approved_private_endpoint:
            return "PROTECTED (Private Link)", []

        rules = config.get("ipSecurityRestrictions") or []
        default_action = config.get("ipSecurityRestrictionsDefaultAction")
        effective_default = self.effective_default_action(rules, default_action)

        if effective_default == "Allow" or self.has_allow_all_rule(rules):
            return "EXPOSED", []

        real_allow_rules = [r for r in rules if r.get("action") == "Allow" and r.get("ipAddress") != "Any"]
        fd_tag_rules = [r for r in real_allow_rules if self.is_front_door_service_tag_rule(r)]
        other_allow_rules = [r for r in real_allow_rules if r not in fd_tag_rules]

        if fd_tag_rules:
            # Every AzureFrontDoor.Backend rule must carry the fdid check: a second service-tag
            # rule without the header lets any Front Door tenant through regardless of the first.
            if all(self.rule_matches_fdid(r, fdid) for r in fd_tag_rules):
                if other_allow_rules:
                    return "PARTIAL — review rules", fd_tag_rules + other_allow_rules
                return "PROTECTED", fd_tag_rules
            return "PARTIAL — any Front Door tenant can reach origin", fd_tag_rules

        if other_allow_rules:
            return "PARTIAL — review rules", other_allow_rules

        return "PROTECTED", []

    def compute_scm_verdict(self, config, main_verdict, public_network_access):
        if config.get("scmIpSecurityRestrictionsUseMain"):
            return "%s (inherits main)" % main_verdict, []

        if public_network_access == "Disabled":
            return "PROTECTED (Private Link)", []

        rules = config.get("scmIpSecurityRestrictions") or []
        default_action = config.get("scmIpSecurityRestrictionsDefaultAction")
        effective_default = self.effective_default_action(rules, default_action)

        if effective_default == "Allow" or self.has_allow_all_rule(rules):
            return "EXPOSED", []

        real_allow_rules = [r for r in rules if r.get("action") == "Allow" and r.get("ipAddress") != "Any"]
        return "RESTRICTED", real_allow_rules

    def policy_has_global_fdid_check(self, policy_xml, fdid):
        if not policy_xml or not fdid:
            return False
        lowered = policy_xml.lower()
        return "check-header" in lowered and self.FDID_HEADER in lowered and fdid.strip().lower() in lowered

    def policy_has_ip_filter(self, policy_xml):
        if not policy_xml:
            return False
        lowered = policy_xml.lower()
        return "<ip-filter" in lowered and 'action="allow"' in lowered

    def compute_apim_verdict(self, service, policy_xml, fdid):
        # Resource Graph rows carry the projected "vnetType"; the ARM GET's properties carry
        # the raw "virtualNetworkType".
        if (service.get("vnetType") or service.get("virtualNetworkType") or "").lower() == "internal":
            return "PROTECTED (internal VNet)"
        if (service.get("publicNetworkAccess") or "").lower() == "disabled":
            return "PROTECTED (no public access)"
        if self.policy_has_global_fdid_check(policy_xml, fdid):
            return "PROTECTED"
        if self.policy_has_ip_filter(policy_xml):
            return "PARTIAL"
        return "EXPOSED"

    def compute_waf_context(self, domain_waf_pairs, waf_policy_lookup):
        issues = set()
        if not domain_waf_pairs or any(waf_id is None for _, waf_id in domain_waf_pairs):
            issues.add("NO WAF")

        for waf_id in {waf_id for _, waf_id in domain_waf_pairs if waf_id}:
            policy = waf_policy_lookup.get(waf_id)
            if not policy:
                continue
            if (policy.get("state") or "").lower() == "disabled":
                issues.add("WAF DISABLED")
            elif (policy.get("mode") or "").lower() == "detection":
                issues.add("WAF NOT BLOCKING")
            if policy.get("sku") == "Standard_AzureFrontDoor" or not policy.get("managedRuleSets"):
                issues.add("NO MANAGED RULES")

        return sorted(issues)

    def verdict_category(self, verdict):
        return verdict.split(" ", 1)[0].split("(", 1)[0].strip().rstrip("—-").strip()

    # ------------------------------------------------------------------
    # Live probe — always runs a plain reachability check; the payload check
    # (XSS-style test string, sent to origin + public domain) is opt-in only.
    # ------------------------------------------------------------------

    def probe_host(self, host, path="/"):
        if not host:
            return None

        cache_key = (host.lower(), path)
        if cache_key in self._probe_cache:
            return self._probe_cache[cache_key]

        headers = {"User-Agent": self.PROBE_USER_AGENT}
        try:
            # max_retries=0: probes intentionally skip http_client's normal exponential
            # backoff/retry loop. Retrying a probe against a customer WAF several times is
            # exactly the kind of anomalous traffic pattern that gets a scanning IP flagged
            # or blocked — one clean attempt per host is the point, not resilience.
            #
            # timeout as (connect, read): a single float applies separately to the connect
            # phase AND to read-between-bytes, so a host that accepts the TCP connection but
            # never responds (common behind a strict NSG/firewall) could otherwise hang for
            # close to 2x PROBE_TIMEOUT_SECONDS. Splitting it caps the real worst case.
            response = http_client.get(
                url="https://%s%s" % (host, path),
                headers=headers,
                allow_redirects=False,
                timeout=(self.PROBE_TIMEOUT_SECONDS / 2, self.PROBE_TIMEOUT_SECONDS),
                max_retries=0,
            )
        except requests.RequestException as exc:
            result = {"reachable": False, "error": exc.__class__.__name__}
            self._probe_cache[cache_key] = result
            return result

        header_keys = {key.lower() for key in response.headers}
        result = {
            "reachable": True,
            "status": response.status_code,
            "via_front_door": "x-azure-ref" in header_keys,
            "server": response.headers.get("Server"),
        }
        self._probe_cache[cache_key] = result
        return result

    def probe_payload(self, host):
        result = self.probe_host(host, path=self.PROBE_PAYLOAD_PATH)
        if result and result.get("reachable"):
            result["blocked"] = result.get("status") == 403
        return result

    def apply_live_probe(self, host, reach_domains, origin_type=None):
        # Always-on plain reachability check.
        origin_probe = self.probe_host(host)
        notes = []
        severity_override = None
        # APIM answers an unmatched path like "/" with 404 before any (global) policy runs, so
        # a 404 there says nothing about whether the fdid check would have blocked a real call.
        inconclusive_statuses = {403, 404} if origin_type == "API Management" else {403}
        probe_confirms_reachable = bool(
            origin_probe and origin_probe.get("reachable") and origin_probe.get("status") not in inconclusive_statuses
        )

        origin_payload_probe = None
        public_payload_probes = {}
        if self._probe_payload_enabled:
            origin_payload_probe = self.probe_payload(host)
            for domain_host, _ in reach_domains or []:
                if domain_host and domain_host != host:
                    public_payload_probes[domain_host] = self.probe_payload(domain_host)

            for domain_host, payload_probe in public_payload_probes.items():
                if (
                    payload_probe and payload_probe.get("blocked")
                    and origin_payload_probe and origin_payload_probe.get("reachable")
                    and not origin_payload_probe.get("blocked")
                ):
                    severity_override = "critical"
                    notes.append(
                        "Confirmed WAF bypass: public domain %s blocked the test payload (403) but "
                        "the origin returned HTTP %s directly."
                        % (domain_host, origin_payload_probe.get("status"))
                    )

        probe_meta = {
            "origin_probe": origin_probe,
            "origin_payload_probe": origin_payload_probe,
            "public_payload_probes": public_payload_probes or None,
        }
        return probe_confirms_reachable, notes, severity_override, probe_meta

    # ------------------------------------------------------------------
    # App Service / APIM config collection
    # ------------------------------------------------------------------

    def has_approved_private_endpoint(self, site_id):
        connections = self.collect_paged(
            "%s/privateEndpointConnections?api-version=%s" % (site_id, self.WEB_API_VERSION),
            label="privateEndpointConnections",
        )
        return any(
            ((c.get("properties") or {}).get("privateLinkServiceConnectionState") or {}).get("status") == "Approved"
            for c in connections
        )

    def get_site_instances(self, site):
        # main site + every deployment slot — slots are frequently forgotten and unrestricted.
        site_id = site.get("id")
        instances = [{"label": "main", "id": site_id, "hostname": site.get("defaultHostName")}]
        for slot in self.collect_paged("%s/slots?api-version=%s" % (site_id, self.WEB_API_VERSION), label="slots"):
            slot_id = slot.get("id")
            slot_props = slot.get("properties") or {}
            if slot_id:
                instances.append({
                    "label": slot.get("name", "slot"),
                    "id": slot_id,
                    "hostname": slot_props.get("defaultHostName"),
                    # A slot's publicNetworkAccess is its own property, independent of the main
                    # site's — Resource Graph only indexes microsoft.web/sites (not .../slots), so
                    # this /slots list call is the only place it's available.
                    "public_network_access": slot_props.get("publicNetworkAccess"),
                })
        return instances

    def get_app_service_evaluation_data(self, site):
        # Fetches everything needed to verdict a site (and its slots) exactly once per site,
        # no matter how many origin groups/profiles route to it. The verdict itself still gets
        # recomputed per encounter (in run()) since the FDID being checked for can differ
        # across Front Door profiles — only the underlying ARM data is cached here.
        site_id = site.get("id")
        if site_id in self._app_service_data_cache:
            return self._app_service_data_cache[site_id]

        status_code, config = self.get_single("%s/config/web?api-version=%s" % (site_id, self.WEB_API_VERSION))
        config_props = config.get("properties") or {}
        has_pe = self.has_approved_private_endpoint(site_id) if status_code == 200 else False

        slot_instances = []
        if status_code == 200:
            for instance in self.get_site_instances(site):
                if instance["label"] == "main":
                    continue
                slot_status_code, slot_config = self.get_single(
                    "%s/config/web?api-version=%s" % (instance["id"], self.WEB_API_VERSION)
                )
                if slot_status_code != 200:
                    continue
                slot_instances.append({
                    "label": instance["label"],
                    "id": instance["id"],
                    "hostname": instance["hostname"],
                    "config_props": slot_config.get("properties") or {},
                    "has_pe": self.has_approved_private_endpoint(instance["id"]),
                    "public_network_access": instance["public_network_access"],
                })

        data = {
            "status_code": status_code,
            "config_props": config_props,
            "has_pe": has_pe,
            "slot_instances": slot_instances,
        }
        self._app_service_data_cache[site_id] = data
        return data

    def get_apim_evaluation_data(self, apim):
        apim_id = apim.get("id")
        if apim_id in self._apim_data_cache:
            return self._apim_data_cache[apim_id]

        status_code, service_detail = self.get_single("%s?api-version=%s" % (apim_id, self.APIM_API_VERSION))
        service_props = service_detail.get("properties") or apim
        # Mirror the App Service path: on 403 (no RBAC to read the service), don't silently fall
        # through to compute_apim_verdict with empty/fallback data — that reads as a real
        # protection check having passed (no fdid check found -> "EXPOSED") when it's actually
        # just an access-denied result. Skip the policy fetch too; it would 403 the same way.
        if status_code == 403:
            data = {"status_code": status_code, "service_props": service_props, "policy_xml": None}
            self._apim_data_cache[apim_id] = data
            return data

        _, policy = self.get_single(
            "%s/policies/policy?format=rawxml&api-version=%s" % (apim_id, self.APIM_API_VERSION)
        )
        data = {
            "status_code": status_code,
            "service_props": service_props,
            "policy_xml": (policy.get("properties") or {}).get("value"),
        }
        self._apim_data_cache[apim_id] = data
        return data

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    SEVERITY_BY_CATEGORY = {
        "EXPOSED": "high",
        "PARTIAL": "medium",
        "RESTRICTED": "low",
        "PROTECTED": "info",
        "UNKNOWN": "low",
        "ACCESS_DENIED": "low",
    }

    def build_classic_front_door_finding(self, profile, subscription_id):
        return make_finding(
            title="Classic Front Door in use: %s" % profile.get("name"),
            desc=(
                "Classic Front Door (Microsoft.Network/frontdoors) profile `%s` was found. This "
                "scan only analyzes Front Door Standard/Premium (Microsoft.Cdn/profiles); classic "
                "Front Door origins were not evaluated for direct exposure and need manual review."
                % profile.get("name")
            ),
            severity="low",
            confidence="high",
            objects=[make_object("front_door_classic", profile.get("id"), profile.get("name"),
                                  subscription_id=subscription_id)],
            rec="Migrate to Front Door Standard/Premium, or manually audit classic Front Door backend pools for direct-access exposure.",
            meta={"scan": self.droplet_name, "front_door_id": profile.get("frontDoorId")},
        )

    # Row order for the downloadable summary table — mirrors the original spec's
    # origin_exposure.csv (one row per origin/slot/SCM host), trimmed to what this scan
    # actually computes.
    # "Exposed" mirrors the original spec's config_verdict -> "Directly reachable" mapping
    # (EXPOSED -> Yes, PARTIAL -> Partially, everything else -> No) rather than a plain
    # boolean, since PARTIAL ("any Front Door tenant can reach origin", etc.) is a real but
    # conditional exposure that a flat Yes/No would flatten away.
    EXPOSED_LABEL_BY_CATEGORY = {"EXPOSED": "Yes", "PARTIAL": "Partially (see notes)"}

    CSV_COLUMNS = [
        "Subscription", "Front Door Profile", "App Service", "Origin Type", "Exposed",
        "URL", "Origin URL", "Category", "Verdict", "Active", "WAF Issues",
        "Live Probe Status", "Via Front Door", "Notes",
    ]

    # The inline table in the finding detail pane is a compact, narrow panel — full URLs (and
    # the "URL" column's comma-joined multi-domain list) blow out its width. Drop them there;
    # the CSV keeps every column since it's opened in a spreadsheet with room to spare.
    TABLE_DISPLAY_COLUMNS = [col for col in CSV_COLUMNS if col not in ("URL", "Origin URL")]

    def build_csv_row(self, subscription_id, front_door_profile, origin_host, origin_type, resource, category,
                       verdict, active, waf_issues, reach_domains, probe_meta, notes):
        origin_probe = (probe_meta or {}).get("origin_probe") or {}
        if origin_probe.get("reachable"):
            probe_status = str(origin_probe.get("status"))
        elif origin_probe.get("reachable") is False:
            probe_status = "unreachable (%s)" % origin_probe.get("error")
        else:
            probe_status = ""

        # The public, Front-Door-facing URL(s) that route to this origin — the entry point a
        # WAF bypass skips past. Same set for the origin, its slots, and its SCM host, since
        # they're all reachable under the same public domain(s).
        public_hosts = sorted({host for host, _ in (reach_domains or []) if host})
        public_urls = ", ".join("https://%s" % host for host in public_hosts)

        return {
            "Subscription": subscription_id or "",
            "Front Door Profile": front_door_profile or "",
            "App Service": (resource or {}).get("name") or "",
            "Origin Type": origin_type,
            "Exposed": self.EXPOSED_LABEL_BY_CATEGORY.get(category, "No"),
            "URL": public_urls,
            "Origin URL": "https://%s" % origin_host if origin_host else "",
            "Category": category,
            "Verdict": verdict,
            "Active": "Yes" if active else "No",
            "WAF Issues": ", ".join(waf_issues) if waf_issues else "",
            "Live Probe Status": probe_status,
            "Via Front Door": "Yes" if origin_probe.get("via_front_door") else "No",
            "Notes": "; ".join(notes) if notes else "",
        }

    SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

    CATEGORY_DESCRIPTIONS = {
        "EXPOSED": "can be reached directly from the internet, bypassing the Front Door WAF.",
        "PARTIAL": "are only partially locked down to Front Door (e.g. any Front Door tenant can reach "
                   "them, or allow rules beyond Front Door need review).",
        "RESTRICTED": "are restricted by IP allow rules but not specifically to this Front Door profile.",
        "UNKNOWN": "could not be matched to an App Service or API Management backend, or their configuration "
                   "could not be read, and were not evaluated.",
        "ACCESS_DENIED": "could not be evaluated — the scanning identity was denied access to their configuration.",
        "PROTECTED": "are protected by config, but the live probe raised notes that need review.",
    }

    CATEGORY_RECOMMENDATIONS = {
        "UNKNOWN": "Manually review these origins for direct-access exposure.",
        "ACCESS_DENIED": "Grant Reader on the affected resources and rerun, or review their access restrictions manually.",
    }

    # Per-category table: the category is the finding itself, so drop Category (and Exposed,
    # which is derived from it);
    # add the IP-restriction rules that drove each verdict (previously per-finding evidence).
    GROUPED_TABLE_COLUMNS = [col for col in CSV_COLUMNS if col not in ("URL", "Origin URL", "Category", "Exposed")] + ["Rules"]

    def origin_severity(self, category, waf_issues, severity_override):
        severity = severity_override or self.SEVERITY_BY_CATEGORY.get(category, "medium")
        if waf_issues and severity == "info":
            severity = "low"
        return severity

    def format_rules(self, evidence_rules):
        parts = []
        for rule in evidence_rules or []:
            # VNet rules carry the subnet in vnetSubnetResourceId and no ipAddress.
            subnet_id = rule.get("vnetSubnetResourceId") or ""
            subnet_parts = subnet_id.rstrip("/").split("/")
            subnet = "%s/%s" % (subnet_parts[-3], subnet_parts[-1]) if len(subnet_parts) >= 3 else subnet_id
            target = rule.get("ipAddress") or subnet or rule.get("tag") or ""
            label = "%s %s" % (rule.get("action") or "", target)
            if rule.get("headers"):
                label += " %s" % json.dumps(rule.get("headers"))
            parts.append(label.strip())
        return "; ".join(parts)

    def build_category_finding(self, category, entries):
        severity = next(
            (sev for sev in self.SEVERITY_ORDER if any(e["severity"] == sev for e in entries)), "info"
        )
        confirmed = any(e["severity_override"] for e in entries)
        rows = [e["row"] for e in entries]

        desc_lines = [
            "%d Front Door origin(s)/slot(s)/SCM host(s) %s"
            % (len(entries), self.CATEGORY_DESCRIPTIONS.get(category, "were classified as %s." % category))
        ]
        if confirmed:
            desc_lines.append("Live payload probe confirmed a WAF bypass on at least one origin (see Notes).")
        waf_issues = sorted({issue for e in entries for issue in e["waf_issues"]})
        if waf_issues:
            desc_lines.append("WAF issues seen on affected routes: %s." % ", ".join(waf_issues))

        return make_finding(
            title="Front Door Origins %s (%d)" % (category, len(entries)),
            desc="\n".join(desc_lines),
            severity=severity,
            confidence="high" if confirmed or category in ("EXPOSED", "PROTECTED") else "medium",
            objects=[e["object"] for e in entries],
            evidence=[{"type": "app_table", "columns": self.GROUPED_TABLE_COLUMNS, "rows": rows}],
            rec=self.CATEGORY_RECOMMENDATIONS.get(
                category,
                "Restrict direct access to these origins to Front Door only, and verify the x-azure-fdid "
                "header check matches each profile's Front Door ID.",
            ),
            meta={
                "scan": self.droplet_name,
                "category": category,
                "origins": [
                    {
                        "origin_host": e["origin_host"],
                        "origin_type": e["origin_type"],
                        "verdict": e["verdict"],
                        "subscription_id": e["subscription_id"],
                        "probe": e["probe_meta"],
                    }
                    for e in entries
                ],
            },
        )

    def build_output_dir(self):
        if self._output_dir is None:
            tenant_id = tokenizer.get_current_tenant_id() or "unknown"
            folder_name = "%s_%s" % (int(datetime.now().timestamp()), self.output_folder_label)
            self._output_dir = os.path.join(PROJECT_ROOT, "output", tenant_id, "csv", folder_name)
            os.makedirs(self._output_dir, exist_ok=True)
        return self._output_dir

    def write_csv_rows(self, rows):
        if not rows:
            return []

        output_dir = self.build_output_dir()
        file_path = os.path.join(output_dir, "origin_exposure.csv")
        with open(file_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self.CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

        console.debug("[↳] Origin exposure table saved: %s" % file_path)
        relative_path = os.path.relpath(file_path, os.path.join(PROJECT_ROOT, "output")).replace("\\", "/")
        return [relative_path]

    def build_summary_finding(self, verdict_counts, total_origins, csv_paths, csv_rows):
        checks = [
            # PROTECTED is good posture — flag it "info" so renderMetrics doesn't paint a high
            # PROTECTED percentage in the red "bad" gradient.
            {"label": category, "bad": count, "total": total_origins, "info": category == "PROTECTED"}
            for category, count in sorted(verdict_counts.items(), key=lambda kv: -kv[1])
        ]
        desc_lines = ["Front Door origin exposure across %d evaluated origins/slots/SCM hosts:" % total_origins]
        for category, count in sorted(verdict_counts.items(), key=lambda kv: -kv[1]):
            pct = round(count / total_origins * 100) if total_origins else 0
            desc_lines.append("  %s: %d (%d%%)" % (category, count, pct))

        return make_finding(
            title="Front Door Origin Exposure Summary",
            desc="\n".join(desc_lines),
            severity="info",
            confidence="high",
            rec="Prioritize EXPOSED origins, then PARTIAL — attacker-controllable Front Door WAF bypass paths. "
                "Download the CSV below for the full origin-by-origin table.",
            # Same rows as the CSV, embedded so the UI can render the table inline (see
            # renderEvidence's "Front Door Origin Exposure" branch in FindingDetailPane.jsx) —
            # the csv_paths download above stays for offline/spreadsheet use.
            evidence=[{"type": "app_table", "columns": self.TABLE_DISPLAY_COLUMNS, "rows": csv_rows}] if csv_rows else [],
            meta={
                "scan": self.droplet_name,
                "metrics": [{"category": "Origin Verdicts", "total": total_origins, "checks": checks}],
                "csv_paths": csv_paths,
            },
        )

    def finalize_and_record(self, grouped, verdict_counts, csv_rows, origin_host, origin_type, resource, verdict,
                             evidence_rules, subscription_id, front_door_profile, waf_issues, active, reach_domains,
                             extra_desc=""):
        # Shared by the main origin, each deployment slot, and the SCM/Kudu host: reconciles
        # the config-based verdict against the live probe, tallies it, and adds the origin
        # to its category group unless it's a clean PROTECTED with nothing for the probe to contradict.
        category = self.verdict_category(verdict)
        probe_confirms_reachable, probe_notes, severity_override, probe_meta = self.apply_live_probe(
            origin_host, reach_domains, origin_type
        )
        origin_probe = probe_meta.get("origin_probe") or {}

        if category == "PROTECTED" and probe_confirms_reachable:
            probe_notes.insert(
                0,
                "Live probe contradicts config analysis: origin responded HTTP %s directly. Needs manual review."
                % origin_probe.get("status"),
            )
            category = "PARTIAL"
        elif category in ("EXPOSED", "PARTIAL") and origin_probe.get("reachable") is False:
            probe_notes.append(
                "Live probe could not reach origin (%s); config verdict could not be confirmed live."
                % origin_probe.get("error")
            )

        verdict_counts[category] = verdict_counts.get(category, 0) + 1
        csv_rows.append(
            self.build_csv_row(
                subscription_id, front_door_profile, origin_host, origin_type, resource, category, verdict,
                active, waf_issues, reach_domains, probe_meta, ([extra_desc] if extra_desc else []) + probe_notes,
            )
        )

        if category != "PROTECTED" or probe_notes:
            row = dict(csv_rows[-1])
            row["Rules"] = self.format_rules(evidence_rules)
            grouped.setdefault(category, []).append({
                "row": row,
                "severity": self.origin_severity(category, waf_issues, severity_override),
                "severity_override": severity_override,
                "waf_issues": waf_issues,
                "origin_host": origin_host,
                "origin_type": origin_type,
                "verdict": verdict,
                "subscription_id": subscription_id,
                "probe_meta": probe_meta,
                "object": make_object("front_door_origin", resource.get("id") if resource else None, origin_host,
                                      subscription_id=subscription_id, backend_type=origin_type),
            })
        return category

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self):
        status.set_phase("Authenticating with ARM")
        self.access_token = tokenizer.get_arm_token()
        if not self.access_token:
            console.error("[!] Could not retrieve a valid ARM access token.")
            return []

        subscriptions = self.get_all_subscriptions()
        if not subscriptions:
            console.warn("[!] No subscriptions found.")
            return []

        self._probe_payload_enabled = settings.get_front_door_probe_payload()

        status.set_phase("Collecting Front Door, WAF, App Service and APIM inventory")
        fd_profiles = self.get_front_door_profiles(subscriptions)
        classic_front_doors = self.get_classic_front_doors(subscriptions)
        waf_policies = self.get_waf_policies(subscriptions)
        app_services = self.get_app_services(subscriptions)
        apim_services = self.get_apim_services(subscriptions)

        waf_policy_lookup = {policy.get("id"): policy for policy in waf_policies if policy.get("id")}
        app_service_lookup = self.build_app_service_lookup(app_services)
        apim_lookup = self.build_apim_lookup(apim_services)

        findings = []
        grouped = {}
        verdict_counts = {}
        csv_rows = []
        total_origins = 0

        for profile in classic_front_doors:
            findings.append(self.build_classic_front_door_finding(profile, profile.get("subscriptionId")))

        for profile_index, profile in enumerate(fd_profiles, start=1):
            profile_id = profile.get("id")
            profile_name = profile.get("name")
            subscription_id = profile.get("subscriptionId")
            fdid = profile.get("frontDoorId")
            status.set_phase(
                "Front Door profile %d/%d: %s" % (profile_index, len(fd_profiles), profile.get("name"))
            )

            topology = self.collect_profile_topology(profile_id)
            domain_lookup = self.build_domain_lookup(topology)
            domain_waf_lookup = self.build_domain_waf_lookup(topology, waf_policy_lookup)
            origin_reach = self.build_origin_reach_map(topology, domain_lookup, domain_waf_lookup)

            for group_id, origins in topology["origins_by_group"].items():
                reach = origin_reach.get((group_id or "").lower(), {"domains": [], "active": False})
                waf_issues = self.compute_waf_context(reach["domains"], waf_policy_lookup)

                for origin in origins:
                    origin_props = origin.get("properties") or origin
                    origin_host = origin_props.get("hostName")
                    if not origin_host:
                        continue
                    origin_enabled = (origin_props.get("enabledState") or "Enabled") != "Disabled"
                    active = reach["active"] and origin_enabled
                    has_private_link = bool(origin_props.get("sharedPrivateLinkResource"))

                    origin_type, resource = self.match_backend(origin_host, app_service_lookup, apim_lookup)
                    total_origins += 1

                    app_service_data = None
                    if has_private_link:
                        verdict, evidence_rules = "PROTECTED (Private Link via Front Door origin)", []
                    elif origin_type == "App Service":
                        app_service_data = self.get_app_service_evaluation_data(resource)
                        if app_service_data["status_code"] == 403:
                            verdict, evidence_rules = "ACCESS_DENIED", []
                        elif app_service_data["status_code"] != 200:
                            verdict, evidence_rules = (
                                "UNKNOWN (config fetch failed: HTTP %s)" % app_service_data["status_code"], []
                            )
                        else:
                            verdict, evidence_rules = self.compute_app_service_verdict(
                                app_service_data["config_props"], fdid, resource.get("publicNetworkAccess"),
                                app_service_data["has_pe"],
                            )
                    elif origin_type == "API Management":
                        apim_data = self.get_apim_evaluation_data(resource)
                        if apim_data["status_code"] == 403:
                            verdict = "ACCESS_DENIED"
                        elif apim_data["status_code"] != 200:
                            # Mirror the App Service path: a failed service read must not fall
                            # through to compute_apim_verdict, which — with policy_xml None —
                            # would report a false "EXPOSED" (no fdid check found) for what is
                            # really an unread config.
                            verdict = "UNKNOWN (config fetch failed: HTTP %s)" % apim_data["status_code"]
                        else:
                            verdict = self.compute_apim_verdict(
                                apim_data["service_props"], apim_data["policy_xml"], fdid
                            )
                        evidence_rules = []
                    else:
                        verdict, evidence_rules = "UNKNOWN", []

                    self.finalize_and_record(
                        grouped, verdict_counts, csv_rows, origin_host, origin_type, resource, verdict,
                        evidence_rules, subscription_id, profile_name, waf_issues, active, reach["domains"],
                    )

                    if app_service_data is not None:
                        for slot in app_service_data["slot_instances"]:
                            # Use the slot's own publicNetworkAccess, not the main site's — they
                            # can differ, and slots are exactly the kind of resource that's
                            # forgotten and left more open than the parent site.
                            slot_verdict, slot_rules = self.compute_app_service_verdict(
                                slot["config_props"], fdid, slot["public_network_access"], slot["has_pe"]
                            )
                            total_origins += 1
                            self.finalize_and_record(
                                grouped, verdict_counts, csv_rows,
                                slot["hostname"] or "%s (slot)" % origin_host, "App Service (slot)",
                                resource, slot_verdict, slot_rules, subscription_id, profile_name, [], active,
                                reach["domains"], extra_desc="Deployment slot `%s`." % slot["label"],
                            )

                        if app_service_data["status_code"] != 200:
                            # No config was read — evaluating empty SCM restrictions would report
                            # a false EXPOSED; the SCM host is as unevaluated as the main site.
                            scm_verdict, scm_rules = verdict, []
                        else:
                            scm_verdict, scm_rules = self.compute_scm_verdict(
                                app_service_data["config_props"], verdict, resource.get("publicNetworkAccess")
                            )
                        total_origins += 1
                        # Derive the SCM host from the site's own defaultHostName, not origin_host:
                        # origin_host can be any hostname the origin was matched on, including a
                        # custom domain bound to the App Service (build_app_service_lookup indexes
                        # hostNames too) — "<custom-domain-label>.scm.azurewebsites.net" would name
                        # a host that doesn't exist and silently mis-probe/mis-report the SCM finding.
                        # The SCM label goes right after the first label of the default hostname:
                        # app.azurewebsites.net -> app.scm.azurewebsites.net, but also
                        # app-hash.region-01.azurewebsites.net -> app-hash.scm.region-01.azurewebsites.net
                        # and app.ase.appserviceenvironment.net -> app.scm.ase.appserviceenvironment.net.
                        scm_source_host = resource.get("defaultHostName") or origin_host
                        first_label, _, rest = scm_source_host.partition(".")
                        scm_host = "%s.scm.%s" % (first_label, rest or "azurewebsites.net")
                        self.finalize_and_record(
                            grouped, verdict_counts, csv_rows,
                            scm_host, "App Service (SCM/Kudu)",
                            resource, scm_verdict, scm_rules, subscription_id, profile_name, [], active,
                            reach["domains"],
                        )

        category_order = ["EXPOSED", "PARTIAL", "RESTRICTED", "ACCESS_DENIED", "UNKNOWN", "PROTECTED"]
        for category in sorted(grouped, key=lambda c: category_order.index(c) if c in category_order else len(category_order)):
            findings.append(self.build_category_finding(category, grouped[category]))

        if total_origins:
            status.set_phase("Writing origin exposure table")
            csv_paths = self.write_csv_rows(csv_rows)
            # Prepended, not appended — the summary is the entry point into this scan's
            # results and should be the first thing a reviewer sees, matching the convention
            # in export_aztop_resource_overviews.py's metrics finding.
            findings = [self.build_summary_finding(verdict_counts, total_origins, csv_paths, csv_rows)] + findings

        status.set_phase("Writing %s Front Door origin exposure findings" % len(findings))
        write_findings_to_disk(findings, source_name=self.droplet_name)

        return findings
