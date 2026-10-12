import json

import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, make_finding, make_object, write_findings_to_disk


class Droplet:
    droplet_name = "Scan: PIM State Checks"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Audits Privileged Identity Management (PIM) coverage for Entra directory\n"
        "roles and Azure RBAC. Flags high-privilege roles with active (non-PIM)\n"
        "permanent assignments and checks for missing eligibility configuration.\n"
        "\n"
        "Requires\n"
        "  Graph : RoleManagement.Read.Directory, PrivilegedAccess.Read.AzureAD\n"
        "  ARM   : Reader on subscriptions"
    )

    entra_target_role_names = [
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Helpdesk Administrator",
    ]

    target_role_severity = {
        "Owner": "high",
        "User Access Administrator": "high",
        "Contributor": "high",
        "Role Based Access Control Administrator": "medium",
    }

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.graph_token = None
        self.graph_access_unavailable = False
        self.graph_access_error = None
        self.pim_policy_read_unavailable = False
        self.pim_policy_read_warning_emitted = False
        self.arm_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False
        self.arm_access_error = None

    def get_graph_headers(self):
        if self.graph_access_unavailable:
            return None
        if not self.graph_token:
            try:
                self.graph_token = tokenizer.get_graph_token()
            except Exception as exc:
                self.graph_access_unavailable = True
                self.graph_access_error = "Could not acquire a Graph token: %s" % exc
                console.warn("[!] %s" % self.graph_access_error)
                return None
        return {
            "Authorization": "Bearer %s" % self.graph_token,
            "Content-Type": "application/json",
        }

    def graph_get_json(self, path):
        headers = self.get_graph_headers()
        if not headers:
            return None
        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=headers)
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code != 200:
            error_code = str(((payload.get("error") or {}).get("code")) or "")
            error_message = ((payload.get("error") or {}).get("message")) or "Unknown Graph error"
            self.graph_access_unavailable = True
            self.graph_access_error = (
                "Graph request failed with HTTP %s for %s%s%s"
                % (
                    response.status_code,
                    path,
                    ": %s" % error_code if error_code else "",
                    " - %s" % error_message if error_message else "",
                )
            )
            console.warn("[!] %s. Entra PIM checks are incomplete." % self.graph_access_error)
            return None
        return payload

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if json_res is None:
            return []
        if "value" in json_res:
            return check_pagination(self.graph_token, json_res, json_res["value"])
        return []

    def get_arm_headers(self):
        if self.arm_access_unavailable:
            return None
        if not self.arm_token:
            try:
                self.arm_token = tokenizer.get_arm_token()
            except Exception as exc:
                self.arm_access_unavailable = True
                self.arm_enrichment_incomplete = True
                self.arm_access_error = "Could not acquire an ARM token: %s" % exc
                self.warn_arm_unavailable(self.arm_access_error)
                return None
        return {
            "Authorization": "Bearer %s" % self.arm_token,
            "Content-Type": "application/json",
        }

    def warn_arm_unavailable(self, message):
        if self.arm_access_warning_emitted:
            return
        console.warn("[!] %s" % message)
        self.arm_access_warning_emitted = True

    def arm_get_json(self, path):
        headers = self.get_arm_headers()
        if not headers:
            return None
        full_url = "https://management.azure.com%s" % path
        response = http_client.get(url=full_url, headers=headers)
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code != 200:
            self.arm_enrichment_incomplete = True
            error_code = str(((payload.get("error") or {}).get("code")) or "")
            if response.status_code in (401, 403):
                self.arm_access_unavailable = True
                self.arm_access_error = "ARM/RBAC access is unavailable (%s%s)" % (
                    response.status_code,
                    ": %s" % error_code if error_code else "",
                )
                self.warn_arm_unavailable(
                    "%s. Azure resource PIM checks are incomplete." % self.arm_access_error
                )
            else:
                console.warn("[!] ARM request failed with HTTP %s for %s" % (response.status_code, path))
            return None
        return payload

    def collect_arm_values(self, path):
        json_res = self.arm_get_json(path)
        if json_res is None:
            return []
        if "value" in json_res:
            return self.append_paginated_arm_values(json_res, json_res["value"])
        return []

    def append_paginated_arm_values(self, json_res, data_objects):
        next_link = json_res.get("nextLink") or json_res.get("@odata.nextLink")
        while next_link:
            headers = self.get_arm_headers()
            if not headers:
                break

            response = http_client.get(url=next_link, headers=headers)
            try:
                json_res = json.loads(response.content or "{}")
            except ValueError:
                json_res = {}

            if response.status_code != 200:
                self.arm_enrichment_incomplete = True
                console.warn("[!] ARM pagination request failed with HTTP %s for %s" % (response.status_code, next_link))
                break

            data_objects += json_res.get("value") or []
            next_link = json_res.get("nextLink") or json_res.get("@odata.nextLink")
        return data_objects

    def get_all_subscriptions(self):
        return self.collect_arm_values("/subscriptions?api-version=2022-12-01")

    def get_role_definitions(self):
        return self.collect_graph_values(
            "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn"
        )

    def get_role_policy_assignment(self, role_definition_id):
        if self.pim_policy_read_unavailable:
            return None

        path = (
            "/v1.0/policies/roleManagementPolicyAssignments"
            "?$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'%20"
            f"and%20roleDefinitionId%20eq%20'{role_definition_id}'&$expand=policy($expand=rules)"
        )
        headers = self.get_graph_headers()
        if not headers:
            return None
        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=headers)
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code == 403:
            self.pim_policy_read_unavailable = True
            if not self.pim_policy_read_warning_emitted:
                error_code = str(((payload.get("error") or {}).get("code")) or "")
                console.warn(
                    "[!] Microsoft Graph denied access to Entra PIM role management policy assignments%s. "
                    "Skipping Entra-role PIM activation-control checks."
                    % (": %s" % error_code if error_code else "")
                )
                self.pim_policy_read_warning_emitted = True
            return None

        if response.status_code == 404:
            return None

        if response.status_code != 200:
            error_code = str(((payload.get("error") or {}).get("code")) or "")
            error_message = ((payload.get("error") or {}).get("message")) or "Unknown Graph error"
            self.pim_policy_read_unavailable = True
            self.graph_access_error = (
                "Graph request failed with HTTP %s for %s%s%s"
                % (
                    response.status_code,
                    path,
                    ": %s" % error_code if error_code else "",
                    " - %s" % error_message if error_message else "",
                )
            )
            console.warn("[!] %s. Skipping Entra-role PIM activation-control checks." % self.graph_access_error)
            return None

        assignments = payload.get("value") or []
        return assignments[0] if assignments else None

    def get_subscription_role_definitions(self, subscription_id):
        return self.collect_arm_values(
            "%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01" % subscription_id
        )

    def get_subscription_role_management_policy_assignments(self, subscription_id):
        return self.collect_arm_values(
            "%s/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01"
            % subscription_id
        )

    def normalize_resource_id(self, resource_id):
        return str(resource_id or "").rstrip("/").lower()

    def get_rule(self, assignment, rule_id):
        policy = (assignment or {}).get("policy") or {}
        for rule in policy.get("rules", []):
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_effective_rule(self, assignment, rule_id):
        rules = ((assignment.get("properties") or {}).get("effectiveRules")) or []
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_entra_missing_activation_controls(self, assignment):
        enablement_rule = self.get_rule(assignment, "Enablement_EndUser_Assignment") or {}
        approval_rule = self.get_rule(assignment, "Approval_EndUser_Assignment") or {}
        authentication_context_rule = self.get_rule(assignment, "AuthenticationContext_EndUser_Assignment") or {}
        enabled_rules = enablement_rule.get("enabledRules") or []
        approval_stages = ((approval_rule.get("setting") or {}).get("approvalStages")) or []
        approval_required = bool((approval_rule.get("setting") or {}).get("isApprovalRequired")) and bool(approval_stages)
        mfa_required = "MultiFactorAuthentication" in enabled_rules
        authentication_context_enabled = bool(authentication_context_rule.get("isEnabled"))
        strong_activation_auth_present = mfa_required or authentication_context_enabled

        missing_controls = []
        if not strong_activation_auth_present:
            missing_controls.append("strong_activation_auth")
        if "Justification" not in enabled_rules:
            missing_controls.append("justification")
        if "Ticketing" not in enabled_rules:
            missing_controls.append("ticketing")
        if not approval_required:
            missing_controls.append("approval")

        return {
            "enablement_rule": enablement_rule,
            "approval_rule": approval_rule,
            "authentication_context_rule": authentication_context_rule,
            "enabled_rules": enabled_rules,
            "mfa_required": mfa_required,
            "approval_required": approval_required,
            "approval_stages": approval_stages,
            "authentication_context_enabled": authentication_context_enabled,
            "strong_activation_auth_present": strong_activation_auth_present,
            "missing_controls": missing_controls,
            "missing_controls_summary": ", ".join(missing_controls),
        }

    def get_resource_missing_activation_controls(self, assignment):
        enablement_rule = self.get_effective_rule(assignment, "Enablement_EndUser_Assignment") or {}
        approval_rule = self.get_effective_rule(assignment, "Approval_EndUser_Assignment") or {}
        enabled_rules = enablement_rule.get("enabledRules") or []
        approval_setting = approval_rule.get("setting") or {}
        approval_stages = approval_setting.get("approvalStages") or []
        approval_required = bool(approval_setting.get("isApprovalRequired")) and bool(approval_stages)

        missing_controls = []
        if "MultiFactorAuthentication" not in enabled_rules:
            missing_controls.append("mfa")
        if "Justification" not in enabled_rules:
            missing_controls.append("justification")
        if "Ticketing" not in enabled_rules:
            missing_controls.append("ticketing")
        if not approval_required:
            missing_controls.append("approval")

        return {
            "enablement_rule": enablement_rule,
            "approval_rule": approval_rule,
            "enabled_rules": enabled_rules,
            "approval_required": approval_required,
            "approval_stages": approval_stages,
            "missing_controls": missing_controls,
            "missing_controls_summary": ", ".join(missing_controls),
        }

    def build_subscription_object(self, subscription):
        return make_object(
            "subscription",
            subscription.get("subscriptionId") or subscription.get("id"),
            subscription.get("displayName") or subscription.get("subscriptionId") or subscription.get("id"),
            state=subscription.get("state"),
        )

    def build_tenant_object(self):
        tenant_id = tokenizer.get_current_tenant_id()
        return make_object("tenant", tenant_id, tenant_id)

    def build_entra_role_object(self, role):
        return make_object(
            "role",
            role.get("id"),
            role.get("displayName"),
            template_id=role.get("templateId"),
        )

    def build_role_object(self, role_name, role_definition_id, scope):
        return make_object(
            "role",
            role_definition_id,
            role_name,
            source="rbac",
            scope=scope,
            severity=self.target_role_severity.get(role_name, "info"),
        )

    def build_entra_policy_object(self, policy_id, policy_name="roleManagementPolicy"):
        return make_object("policy", policy_id, policy_name)

    def build_policy_object(self, assignment):
        properties = assignment.get("properties") or {}
        return make_object(
            "policy",
            properties.get("policyId"),
            "roleManagementPolicy",
            scope=properties.get("scope"),
            role_definition_id=properties.get("roleDefinitionId"),
        )

    def add_entra_pim_access_gap_finding(self, reason=None):
        self.findings.append(make_finding(
            title="Entra PIM activation controls could not be assessed",
            desc=(
                "Microsoft Graph access to role management policy data was unavailable, so the scan could "
                "not evaluate MFA, approval, justification, ticketing, or authentication-context "
                "requirements for privileged Entra roles."
            ),
            severity="medium",
            confidence="medium",
            objects=[self.build_tenant_object()],
            evidence=[{
                "assessment": "entra_pim_activation_controls",
                "graph_policy_data_read_available": False,
                "policy_assignment_read_available": False,
                "reason": reason,
                "target_roles": self.entra_target_role_names,
            }],
            rec=(
                "Grant the reader identity access needed to read Entra PIM role management policies, "
                "such as RoleManagementPolicy.Read.Directory and a supported Entra role."
            ),
            meta={"scan": self.droplet_name, "category": "entra_pim_policy_access"},
        ))

    def add_resource_pim_access_gap_finding(self, reason=None):
        self.findings.append(make_finding(
            title="Azure resource PIM activation controls could not be assessed",
            desc=(
                "Azure Resource Manager access to role management policy data was unavailable, so the scan could "
                "not evaluate MFA, approval, justification, or ticketing requirements for high-impact Azure RBAC roles."
            ),
            severity="medium",
            confidence="medium",
            objects=[self.build_tenant_object()],
            evidence=[{
                "assessment": "azure_resource_pim_activation_controls",
                "arm_policy_data_read_available": False,
                "reason": reason,
                "target_roles": sorted(self.target_role_severity.keys()),
            }],
            rec=(
                "Run the scan with Azure Resource Manager access that can list subscriptions, role definitions, "
                "and role management policy assignments at the scopes being assessed."
            ),
            meta={"scan": self.droplet_name, "category": "resource_pim_policy_access"},
        ))

    def add_entra_findings(self, role_definitions):
        if self.graph_access_unavailable:
            self.add_entra_pim_access_gap_finding(self.graph_access_error)
            return

        role_by_name = {
            role.get("displayName"): role
            for role in role_definitions
            if role.get("displayName")
        }

        coverage_gap_recorded = False
        for role_name in self.entra_target_role_names:
            if self.pim_policy_read_unavailable:
                if not coverage_gap_recorded:
                    self.add_entra_pim_access_gap_finding(
                        self.graph_access_error or "Graph denied role management policy assignment reads."
                    )
                    coverage_gap_recorded = True
                break

            role = role_by_name.get(role_name)
            if not role:
                console.debug("[i] Role definition not found for %s; skipping Entra PIM activation check." % role_name)
                continue

            status.set_phase("Checking Entra PIM activation requirements for %s" % role_name)
            assignment = self.get_role_policy_assignment(role.get("id"))
            if self.pim_policy_read_unavailable:
                if not coverage_gap_recorded:
                    self.add_entra_pim_access_gap_finding(
                        self.graph_access_error or "Graph denied role management policy assignment reads."
                    )
                    coverage_gap_recorded = True
                break

            if not assignment:
                self.findings.append(make_finding(
                    title="PIM policy assignment was not returned for a privileged Entra role",
                    desc=(
                        "Microsoft Graph did not return a role management policy assignment for a privileged "
                        "Entra role at tenant scope. The role's PIM activation controls could not be assessed."
                    ),
                    severity="medium",
                    confidence="medium",
                    objects=[self.build_tenant_object(), self.build_entra_role_object(role)],
                    evidence=[{
                        "role_definition_id": role.get("id"),
                        "role_name": role_name,
                        "scope_id": "/",
                        "scope_type": "DirectoryRole",
                        "policy_assignment_present": False,
                    }],
                    rec=(
                        "Review the role's PIM policy in Entra ID and confirm activation controls are configured "
                        "for tenant-scope assignments."
                    ),
                    meta={"scan": self.droplet_name, "category": "entra_pim_policy_coverage"},
                ))
                continue

            activation_controls = self.get_entra_missing_activation_controls(assignment)
            missing_controls = activation_controls["missing_controls"]
            if not missing_controls:
                continue

            severity = "high"
            if "strong_activation_auth" not in missing_controls:
                severity = "medium"

            self.findings.append(make_finding(
                title="Entra PIM activation controls are weak for a privileged role",
                desc="A privileged Entra role has one or more missing activation guardrails in PIM.",
                severity=severity,
                confidence="high",
                objects=[
                    self.build_tenant_object(),
                    self.build_entra_role_object(role),
                    self.build_entra_policy_object(assignment.get("policyId")),
                ],
                evidence=[{
                    "role_definition_id": role.get("id"),
                    "role_name": role_name,
                    "policy_assignment_id": assignment.get("id"),
                    "policy_id": assignment.get("policyId"),
                    "scope_id": assignment.get("scopeId"),
                    "scope_type": assignment.get("scopeType"),
                    "enablement_rule_id": activation_controls["enablement_rule"].get("id"),
                    "approval_rule_id": activation_controls["approval_rule"].get("id"),
                    "authentication_context_rule_id": activation_controls["authentication_context_rule"].get("id"),
                    "enabled_rules": activation_controls["enabled_rules"],
                    "missing_controls": missing_controls,
                    "missing_controls_summary": activation_controls["missing_controls_summary"],
                    "mfa_required": activation_controls["mfa_required"],
                    "authentication_context_enabled": activation_controls["authentication_context_enabled"],
                    "authentication_context_claim_value": activation_controls["authentication_context_rule"].get("claimValue"),
                    "strong_activation_auth_present": activation_controls["strong_activation_auth_present"],
                    "justification_required": "justification" not in missing_controls,
                    "ticketing_required": "ticketing" not in missing_controls,
                    "approval_required": activation_controls["approval_required"],
                    "approval_stages": activation_controls["approval_stages"],
                }],
                rec=(
                    "Require MFA or a Conditional Access authentication context, plus justification, ticket "
                    "information, and approval for privileged-role activation where operationally feasible."
                ),
                meta={"scan": self.droplet_name, "category": "entra_pim_activation"},
            ))

    def add_findings_for_subscription(self, subscription, role_definitions, policy_assignments):
        role_definitions_by_id = {}
        for role_definition in role_definitions:
            role_name = ((role_definition.get("properties") or {}).get("roleName")) or role_definition.get("name")
            if role_name in self.target_role_severity:
                role_definitions_by_id[self.normalize_resource_id(role_definition.get("id"))] = role_definition

        assignments_by_role_definition_id = {}
        for assignment in policy_assignments:
            role_definition_id = ((assignment.get("properties") or {}).get("roleDefinitionId")) or ""
            assignments_by_role_definition_id[self.normalize_resource_id(role_definition_id)] = assignment

        for normalized_role_definition_id, role_definition in role_definitions_by_id.items():
            role_definition_id = role_definition.get("id")
            role_name = ((role_definition.get("properties") or {}).get("roleName")) or role_definition.get("name")
            assignment = assignments_by_role_definition_id.get(normalized_role_definition_id)
            if not assignment:
                self.findings.append(make_finding(
                    title="Subscription-scope Azure RBAC role lacks a PIM policy assignment",
                    desc=(
                        "A high-impact Azure RBAC role did not return a role management policy assignment at the "
                        "subscription scope. This can indicate PIM is not configured for that role at this scope."
                    ),
                    severity=self.target_role_severity.get(role_name, "medium"),
                    confidence="medium",
                    objects=[
                        self.build_subscription_object(subscription),
                        self.build_role_object(role_name, role_definition_id, subscription.get("id")),
                    ],
                    evidence=[{
                        "subscription_id": subscription.get("subscriptionId"),
                        "subscription_name": subscription.get("displayName"),
                        "scope": subscription.get("id"),
                        "role_source": "azure_rbac",
                        "role_definition_id": role_definition_id,
                        "role_name": role_name,
                        "policy_assignment_present": False,
                    }],
                    rec="Review whether Azure resource PIM is configured for this role at the subscription scope.",
                    meta={"scan": self.droplet_name, "category": "resource_pim_coverage"},
                ))
                continue

            activation_controls = self.get_resource_missing_activation_controls(assignment)
            missing_controls = activation_controls["missing_controls"]
            if not missing_controls:
                continue

            severity = self.target_role_severity.get(role_name, "medium")
            if "mfa" not in missing_controls and severity == "high":
                severity = "medium"

            self.findings.append(make_finding(
                title="Azure resource PIM activation controls are weak for a subscription-scope RBAC role",
                desc=(
                    "A high-impact Azure RBAC role has one or more missing activation guardrails in PIM at the "
                    "subscription scope."
                ),
                severity=severity,
                confidence="high",
                objects=[
                    self.build_subscription_object(subscription),
                    self.build_role_object(role_name, role_definition_id, subscription.get("id")),
                    self.build_policy_object(assignment),
                ],
                evidence=[{
                    "subscription_id": subscription.get("subscriptionId"),
                    "subscription_name": subscription.get("displayName"),
                    "scope": subscription.get("id"),
                    "role_source": "azure_rbac",
                    "role_definition_id": role_definition_id,
                    "role_name": role_name,
                    "policy_assignment_id": assignment.get("id"),
                    "policy_id": (assignment.get("properties") or {}).get("policyId"),
                    "enabled_rules": activation_controls["enabled_rules"],
                    "missing_controls": missing_controls,
                    "missing_controls_summary": activation_controls["missing_controls_summary"],
                    "mfa_required": "mfa" not in missing_controls,
                    "justification_required": "justification" not in missing_controls,
                    "ticketing_required": "ticketing" not in missing_controls,
                    "approval_required": activation_controls["approval_required"],
                    "approval_stages": activation_controls["approval_stages"],
                    "approval_rule_id": activation_controls["approval_rule"].get("id"),
                    "enablement_rule_id": activation_controls["enablement_rule"].get("id"),
                }],
                rec=(
                    "Require MFA, justification, ticket information, and approval for end-user activation of "
                    "high-impact Azure RBAC roles in PIM where operationally feasible."
                ),
                meta={"scan": self.droplet_name, "category": "resource_pim_activation"},
            ))

    def run(self):
        self.findings = []
        self.graph_token = None
        self.graph_access_unavailable = False
        self.graph_access_error = None
        self.pim_policy_read_unavailable = False
        self.pim_policy_read_warning_emitted = False
        self.arm_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False
        self.arm_access_error = None

        status.set_phase("Collecting Entra role definitions")
        role_definitions = self.get_role_definitions()
        self.add_entra_findings(role_definitions)

        status.set_phase("Collecting subscriptions")
        subscriptions = self.get_all_subscriptions()
        resource_pim_access_gap_recorded = False
        if self.arm_access_unavailable:
            self.add_resource_pim_access_gap_finding(self.arm_access_error)
            resource_pim_access_gap_recorded = True

        total_subscriptions = len(subscriptions)
        for index, subscription in enumerate(subscriptions, start=1):
            if self.arm_access_unavailable:
                if not resource_pim_access_gap_recorded:
                    self.add_resource_pim_access_gap_finding(self.arm_access_error)
                    resource_pim_access_gap_recorded = True
                break

            subscription_label = (
                subscription.get("displayName")
                or subscription.get("subscriptionId")
                or subscription.get("id")
            )
            status.set_phase("Subscription %s/%s: %s" % (index, total_subscriptions, subscription_label))

            role_definitions = self.get_subscription_role_definitions(subscription.get("id"))
            policy_assignments = self.get_subscription_role_management_policy_assignments(subscription.get("id"))
            self.add_findings_for_subscription(subscription, role_definitions, policy_assignments)

        if self.arm_access_unavailable and not resource_pim_access_gap_recorded:
            self.add_resource_pim_access_gap_finding(self.arm_access_error)

        status.set_phase("Writing %s PIM findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
