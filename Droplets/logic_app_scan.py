"""
Logic and Function App Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Collects Logic Apps (Microsoft.Logic/workflows) and Function Apps
(Microsoft.Web/sites kind=functionapp) across all accessible subscriptions,
normalises each into a common record schema, then runs the rule set from
logic_app_scan_rules.py to produce security findings.

Data flow:
  subscriptions
    └─ per subscription:
         ├─ Logic Apps  → build_logic_app_record()
         │                 ├─ build_logic_trigger_record()  (one per trigger)
         │                 └─ _logic_app_ip_restricted()
         └─ Function Apps → collect_function_app_records()
                             ├─ get_function_app_config()
                             ├─ get_functions_for_site()    (skipped if stopped)
                             ├─ get_function_app_auth_settings()
                             └─ build_function_app_record()
                                 └─ build_function_trigger_record()

ARM permissions required: Reader on target subscriptions.
"""

import json
from urllib.parse import parse_qs, urlparse

import util.console as console
import util.error_logger as error_logger
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from ScanRules.logic_app_scan_rules import SCAN_RULES, BATCH_SCAN_RULES
from Objects.Core import check_pagination, write_findings_to_disk


class Droplet:
    droplet_name = "Scan: Logic and Function App Review"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Reviews Logic Apps and Function Apps across all subscriptions for\n"
        "security misconfigurations: unauthenticated HTTP triggers, insecure\n"
        "connector patterns, and other rule-based findings.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    # ARM API versions pinned per resource provider.
    logic_api_version = "2019-05-01"
    web_api_version = "2022-03-01"
    subscriptions_api_version = "2022-12-01"

    # Logic App HTTP request trigger type/kind values per Microsoft docs.
    # Older workflow definitions may omit `kind`; we accept both.
    request_trigger_types = {"request", "manual"}
    request_trigger_kinds = {"http"}

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []

    # ── ARM helpers ───────────────────────────────────────────────────────────

    def arm_get(self, url, **kwargs):
        full_url = "https://management.azure.com%s" % url
        headers = {
            "Authorization": "Bearer %s" % tokenizer.get_arm_token(),
            "Content-Type": "application/json",
        }
        return http_client.get(url=full_url, headers=headers, **kwargs)

    def arm_post(self, url, payload=None, **kwargs):
        full_url = "https://management.azure.com%s" % url
        headers = {
            "Authorization": "Bearer %s" % tokenizer.get_arm_token(),
            "Content-Type": "application/json",
        }
        return http_client.post(url=full_url, headers=headers, json=payload or {}, **kwargs)

    # ── ARM API calls ─────────────────────────────────────────────────────────

    def get_all_subscriptions(self):
        return self.arm_get("/subscriptions?api-version=%s" % self.subscriptions_api_version)

    def get_all_logic_apps(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Logic/workflows?api-version=%s"
            % (subscription_id, self.logic_api_version)
        )

    def get_all_web_sites(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Web/sites?api-version=%s"
            % (subscription_id, self.web_api_version)
        )

    def get_function_app_config(self, subscription_id, resource_group, site_name):
        # Returns the site's web config (HTTP version, TLS settings, CORS, IP
        # restrictions, client cert mode, etc.).
        return self.arm_get(
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/config/web?api-version=%s"
            % (subscription_id, resource_group, site_name, self.web_api_version)
        )

    def get_functions_for_site(self, subscription_id, resource_group, site_name, **kwargs):
        # Lists individual functions under a Function App, including their binding
        # config (which reveals authLevel for HTTP triggers).
        return self.arm_get(
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/functions?api-version=%s"
            % (subscription_id, resource_group, site_name, self.web_api_version),
            **kwargs,
        )

    def get_function_app_auth_settings(self, subscription_id, resource_group, site_name):
        # authsettingsV2 exposes the EasyAuth (App Service Authentication) state.
        return self.arm_get(
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/config/authsettingsV2?api-version=%s"
            % (subscription_id, resource_group, site_name, self.web_api_version)
        )

    def get_logic_trigger_callback_url(self, subscription_id, resource_group, workflow_name, trigger_name):
        # listCallbackUrl returns the full invocation URL including the SAS `sig`
        # parameter (if present). We use this to determine auth mode — see
        # callback_auth_mode() below.
        return self.arm_post(
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Logic/workflows/%s/triggers/%s/listCallbackUrl?api-version=%s"
            % (subscription_id, resource_group, workflow_name, trigger_name, self.logic_api_version),
            payload={"keyType": "Primary"},
        )

    # ── Pagination / utilities ────────────────────────────────────────────────

    def collect_values(self, response, token):
        json_res = json.loads(response.content or "{}")
        if "value" in json_res:
            return check_pagination(token, json_res, json_res["value"])
        return []

    def get_resource_group_from_id(self, resource_id):
        parts = (resource_id or "").split("/")
        try:
            return parts[parts.index("resourceGroups") + 1]
        except (ValueError, IndexError):
            return ""

    # ── Auth / access detection ───────────────────────────────────────────────

    def callback_auth_mode(self, callback_url):
        """
        Derives the Logic App trigger auth mode from its callback URL.

        Azure embeds a `sig` (shared access signature) query parameter in the
        callback URL when SAS authentication is configured. If no `sig` is
        present the trigger accepts requests without any credential, so we
        classify it as anonymous.
        """
        if not callback_url:
            return "unknown"
        query = parse_qs(urlparse(callback_url).query)
        if query.get("sig"):
            return "sharedAccessSignature"
        return "anonymous"

    def is_logic_web_request_trigger(self, trigger_definition):
        """
        Returns True for inbound HTTP request triggers.

        The ARM schema represents these as type=Request (or legacy type=manual)
        with kind=Http. Older workflow definitions may omit `kind` entirely, in
        which case we accept the trigger if the type matches.
        """
        trigger_type = (trigger_definition.get("type") or "").lower()
        trigger_kind = (trigger_definition.get("kind") or "").lower()

        if trigger_type not in self.request_trigger_types:
            return False

        return not trigger_kind or trigger_kind in self.request_trigger_kinds

    def is_public_web_access(self, app_properties, config_properties):
        """
        Returns True if the Function App is reachable from the public internet.

        Three mechanisms can block public access:
          1. publicNetworkAccess set to "Disabled" (platform-level kill switch).
          2. ipSecurityRestrictionsDefaultAction explicitly set to "Deny"
             (allowlist in effect — only listed ranges can reach the app).
          3. An explicit "Deny all" catch-all rule in ipSecurityRestrictions
             (Azure portal always appends one when IP restrictions are configured;
             the ipSecurityRestrictionsDefaultAction field may be absent from
             older ARM responses so we cannot rely on it alone).
        """
        public_network_access = (
            config_properties.get("publicNetworkAccess")
            or app_properties.get("publicNetworkAccess")
            or "Enabled"
        )
        if str(public_network_access).lower() == "disabled":
            return False

        ip_restrictions = config_properties.get("ipSecurityRestrictions") or []
        if not ip_restrictions:
            return True

        default_action = (config_properties.get("ipSecurityRestrictionsDefaultAction") or "").lower()
        if default_action == "deny":
            return False

        # Azure portal always appends a "Deny all" catch-all rule when IP
        # restrictions are set up.  ipSecurityRestrictionsDefaultAction may be
        # absent from older ARM payloads, so also scan the rule list for an
        # explicit deny covering all addresses (ipAddress "Any", "0.0.0.0/0",
        # or "*") — any such rule implies an effective allowlist.
        wildcard_ips = {"any", "0.0.0.0/0", "*"}
        has_deny_all = any(
            isinstance(r, dict)
            and (r.get("action") or "").lower() == "deny"
            and (r.get("ipAddress") or "").strip().lower() in wildcard_ips
            for r in ip_restrictions
        )
        if has_deny_all:
            return False

        return True

    # ── Record builders ───────────────────────────────────────────────────────

    def build_logic_trigger_record(self, workflow, trigger_name, trigger_definition, subscription_id):
        """
        Builds a normalised trigger dict for a single Logic App trigger.

        For HTTP request triggers we call listCallbackUrl to obtain the actual
        invocation URL. The presence or absence of the `sig` query parameter
        determines whether authentication is required (see callback_auth_mode).
        If the callback URL fetch fails we record external_access=False so the
        trigger is excluded from reachability findings rather than silently
        misclassified.
        """
        is_http = self.is_logic_web_request_trigger(trigger_definition)
        callback_url = None
        auth_mode = "unknown"
        external_access = False

        if is_http:
            resource_group = self.get_resource_group_from_id(workflow.get("id"))
            try:
                response = self.get_logic_trigger_callback_url(
                    subscription_id=subscription_id,
                    resource_group=resource_group,
                    workflow_name=workflow.get("name"),
                    trigger_name=trigger_name,
                )
                payload = json.loads(response.content)
                callback_url = payload.get("value")
                external_access = bool(callback_url)
                auth_mode = self.callback_auth_mode(callback_url)
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Logic App trigger callback fetch failed: %s/%s" % (
                        workflow.get("name"),
                        trigger_name,
                    )
                )
                console.warn("[!] Failed to fetch callback URL for Logic App trigger %s/%s: %s" % (
                    workflow.get("name"),
                    trigger_name,
                    exc,
                ))

        return {
            "id": "%s/triggers/%s" % (workflow.get("id"), trigger_name),
            "name": trigger_name,
            "type": trigger_definition.get("type"),
            "kind": trigger_definition.get("kind"),
            "is_http": is_http,
            "external_access": external_access,
            "auth_mode": auth_mode,
            "callback_url": callback_url,
            "config_path": "properties.definition.triggers.%s" % trigger_name,
        }

    def build_logic_app_record(self, subscription, workflow):
        """
        Builds a normalised record for a Logic App workflow.

        ip_restricted is resolved once at the workflow level and then stamped
        onto every trigger, since access restrictions in Logic Apps apply to the
        entire workflow rather than individual triggers.
        """
        properties = workflow.get("properties") or {}
        definition = properties.get("definition") or {}
        ip_restricted = self._logic_app_ip_restricted(workflow)
        triggers = []

        for trigger_name, trigger_definition in (definition.get("triggers") or {}).items():
            if not isinstance(trigger_definition, dict):
                continue
            trigger = self.build_logic_trigger_record(
                workflow=workflow,
                trigger_name=trigger_name,
                trigger_definition=trigger_definition,
                subscription_id=subscription["id"],
            )
            trigger["ip_restricted"] = ip_restricted
            triggers.append(trigger)

        return {
            "platform": "logicApp",
            "id": workflow.get("id"),
            "name": workflow.get("name"),
            "subscription_id": subscription.get("id"),
            "subscription_name": subscription.get("name"),
            "resource_group": self.get_resource_group_from_id(workflow.get("id")),
            "region": workflow.get("location"),
            "public_access": any(trigger.get("external_access") for trigger in triggers),
            "triggers": triggers,
            "text_blobs": [
                {
                    "source": "workflow_definition",
                    "content": json.dumps(definition, indent=2),
                }
            ],
            "raw": workflow,
        }

    def build_function_trigger_record(self, site, function_payload, public_access):
        """
        Extracts HTTP trigger entries from a single function's binding config.

        Function App auth is set per-trigger via the binding's `authLevel` field
        (anonymous / function / admin). Unlike Logic Apps there is no callback
        URL to inspect — auth level comes directly from the deployment config.
        """
        properties = function_payload.get("properties") or {}
        config = properties.get("config") or {}
        bindings = config.get("bindings") or []

        triggers = []
        for binding in bindings:
            binding_type = (binding.get("type") or "").lower()
            if binding_type != "httptrigger":
                continue

            auth_level = (binding.get("authLevel") or binding.get("authlevel") or "unknown").lower()
            triggers.append({
                "id": function_payload.get("id"),
                "name": function_payload.get("name"),
                "type": binding.get("type"),
                "is_http": True,
                "external_access": public_access,
                "auth_mode": "anonymous" if auth_level == "anonymous" else auth_level,
                "callback_url": None,
                "config_path": "properties.config.bindings",
            })

        return triggers

    def build_function_app_record(self, subscription, site, config_payload, function_payloads, auth_payload=None):
        """
        Builds a normalised record for a Function App site.

        clientCertEnabled / clientCertMode arrive as separate fields in older
        API responses; we normalise them into a single client_cert_mode string
        so rules only need to check one field.

        easyauth_enabled is read from the authsettingsV2 platform block. A None
        value means the auth settings endpoint was unreachable or returned no
        data; rules treat None as "unknown" rather than "disabled".
        """
        site_properties = site.get("properties") or {}
        config_properties = (config_payload.get("properties") or {}) if isinstance(config_payload, dict) else {}
        public_access = self.is_public_web_access(site_properties, config_properties)

        # Normalise the two client-cert fields into one value.
        client_cert_enabled = site_properties.get("clientCertEnabled")
        client_cert_mode = site_properties.get("clientCertMode")
        if client_cert_enabled is False:
            client_cert_mode = "Disabled"
        elif client_cert_enabled is True and not client_cert_mode:
            client_cert_mode = "Required"

        http_version = "2.0" if config_properties.get("http20Enabled") else "1.1"
        cors_allowed_origins = list((config_properties.get("cors") or {}).get("allowedOrigins") or [])

        # EasyAuth state lives under properties.platform.enabled in authsettingsV2.
        easyauth_enabled = None
        if isinstance(auth_payload, dict):
            platform_block = (auth_payload.get("properties") or {}).get("platform") or {}
            raw_enabled = platform_block.get("enabled")
            if raw_enabled is not None:
                easyauth_enabled = bool(raw_enabled)

        triggers = []
        text_blobs = [
            {
                "source": "site_resource",
                "content": json.dumps(site, indent=2),
            },
            {
                "source": "site_config",
                "content": json.dumps(config_payload or {}, indent=2),
            },
        ]

        for function_payload in function_payloads:
            triggers.extend(self.build_function_trigger_record(site, function_payload, public_access))
            text_blobs.append({
                "source": "function_definition:%s" % function_payload.get("name"),
                "content": json.dumps(function_payload, indent=2),
            })

        return {
            "platform": "functionApp",
            "id": site.get("id"),
            "name": site.get("name"),
            "subscription_id": subscription.get("id"),
            "subscription_name": subscription.get("name"),
            "resource_group": self.get_resource_group_from_id(site.get("id")),
            "region": site.get("location"),
            "public_access": public_access,
            "https_only": site_properties.get("httpsOnly"),
            "http_version": http_version,
            "minimum_inbound_tls_version": config_properties.get("minTlsVersion"),
            "client_cert_mode": client_cert_mode or "Unknown",
            "cors_allowed_origins": cors_allowed_origins,
            "easyauth_enabled": easyauth_enabled,
            "triggers": triggers,
            "text_blobs": text_blobs,
            "raw": site,
        }

    def _logic_app_ip_restricted(self, workflow):
        """
        Returns True if the Logic App has a meaningful IP allowlist on its
        trigger access control.

        ARM path: properties.accessControl.triggers.allowedCallerIpAddresses
        (absent when no restriction is configured).

        We treat wildcard ranges (0.0.0.0-255.255.255.255, 0.0.0.0/0, *) as
        equivalent to no restriction — they are sometimes written by tooling
        when access control is intentionally left open.
        """
        properties = workflow.get("properties") or {}
        access_control = properties.get("accessControl") or {}
        trigger_access = access_control.get("triggers") or {}
        allowed_ips = trigger_access.get("allowedCallerIpAddresses") or []
        if not allowed_ips:
            return False
        wildcards = {"0.0.0.0-255.255.255.255", "0.0.0.0/0", "*", "any", ""}
        return not any(
            (ip.get("addressRange") or "").strip().lower() in wildcards
            for ip in allowed_ips
            if isinstance(ip, dict)
        )

    def is_function_app(self, site):
        # The `kind` field on Microsoft.Web/sites contains "functionapp" for
        # Function Apps, potentially alongside other tags (e.g. "linux,functionapp").
        kind = (site.get("kind") or "").lower()
        return "functionapp" in kind

    # ── Collection ────────────────────────────────────────────────────────────

    def collect_logic_app_records(self, subscription):
        workflows = self.collect_values(self.get_all_logic_apps(subscription["id"]), tokenizer.get_arm_token())
        records = []
        for workflow in workflows:
            try:
                records.append(self.build_logic_app_record(subscription, workflow))
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Logic App record build failed: %s" % workflow.get("name")
                )
                console.warn("[!] Skipping Logic App %s: %s" % (workflow.get("name"), exc))
        return records

    def collect_function_app_records(self, subscription):
        """
        Collects Function App records for a subscription.

        Config and function listings are fetched separately because they require
        additional ARM calls beyond the site list. Function enumeration is skipped
        for stopped apps — the /functions endpoint returns stale or empty data
        for stopped sites, and triggering a cold-start just to enumerate is
        undesirable. Config and auth settings are still collected for stopped apps
        because those properties are meaningful regardless of runtime state.
        """
        sites = self.collect_values(self.get_all_web_sites(subscription["id"]), tokenizer.get_arm_token())
        function_sites = [site for site in sites if self.is_function_app(site)]

        records = []
        for site in function_sites:
            resource_group = self.get_resource_group_from_id(site.get("id"))
            site_name = site.get("name")
            site_state = ((site.get("properties") or {}).get("state") or "").lower()
            config_payload = {}
            function_payloads = []

            try:
                config_payload = json.loads(
                    self.get_function_app_config(subscription["id"], resource_group, site_name).content
                )
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Function App config fetch failed: %s" % site_name
                )
                console.warn("[!] Failed to fetch config for Function App %s: %s" % (site_name, exc))

            if site_state != "running":
                console.debug("[↳] Skipping function enumeration for stopped app: %s (state=%s)" % (site_name, site_state or "unknown"))
            else:
                try:
                    function_payloads = self.collect_values(
                        self.get_functions_for_site(
                            subscription["id"], resource_group, site_name,
                            timeout=20, max_retries=2,
                        ),
                        tokenizer.get_arm_token(),
                    )
                except Exception as exc:
                    error_logger.log_current_exception(
                        context="Function App functions fetch failed: %s" % site_name
                    )
                    # Timeouts here are common for consumption-plan apps (cold start).
                    # The app is still scanned for all baseline checks; trigger detail
                    # will simply be absent for this app.
                    console.debug("[↳] Could not fetch function list for %s (trigger detail unavailable): %s" % (site_name, exc))

            auth_payload = None
            try:
                auth_response = self.get_function_app_auth_settings(subscription["id"], resource_group, site_name)
                auth_payload = json.loads(auth_response.content)
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Function App auth settings fetch failed: %s" % site_name
                )
                console.warn("[!] Failed to fetch auth settings for Function App %s: %s" % (site_name, exc))

            try:
                records.append(
                    self.build_function_app_record(subscription, site, config_payload, function_payloads, auth_payload)
                )
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Function App record build failed: %s" % site_name
                )
                console.warn("[!] Skipping Function App %s: %s" % (site_name, exc))

        return records

    def collect_target_records(self):
        """Iterates all accessible subscriptions and gathers Logic App and
        Function App records into a single flat list for rule evaluation."""
        subscriptions = self.collect_values(self.get_all_subscriptions(), tokenizer.get_arm_token())

        records = []
        total_subscriptions = len(subscriptions)
        for index, subscription in enumerate(subscriptions, start=1):
            subscription_record = {
                "id": subscription.get("subscriptionId") or subscription.get("id"),
                "name": subscription.get("displayName"),
            }
            status.set_phase("Subscription %s/%s: %s" % (index, total_subscriptions, subscription_record["name"]))
            try:
                records.extend(self.collect_logic_app_records(subscription_record))
                records.extend(self.collect_function_app_records(subscription_record))
            except Exception as exc:
                error_logger.log_current_exception(
                    context="Subscription scan failed: %s" % subscription_record["name"]
                )
                console.warn("[!] Skipping subscription %s: %s" % (subscription_record["name"], exc))

        return records

    # ── Rule execution ────────────────────────────────────────────────────────

    def run_rules(self, records):
        """
        Evaluates all registered rules against the collected records.

        SCAN_RULES are called once per record (per-app findings).
        BATCH_SCAN_RULES are called once with the full record list (consolidated
        findings that aggregate all affected apps into a single table).
        """
        findings = []
        for record in records:
            for rule in SCAN_RULES:
                findings.extend(rule(record, self.droplet_name))
        for rule in BATCH_SCAN_RULES:
            findings.extend(rule(records, self.droplet_name))
        return findings

    def run(self):
        status.set_phase("Collecting Logic Apps and Function Apps")
        records = self.collect_target_records()
        status.set_phase("Running review rules across %s records" % len(records))
        self.findings = self.run_rules(records)
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
