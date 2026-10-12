import json

import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import make_finding, make_object, write_findings_to_disk


class Droplet:
    droplet_name = "Scan: Entra ID State Checks"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Audits tenant-wide Entra ID configuration for weak defaults: app\n"
        "registration by non-admins, tenant creation by non-admins, overly\n"
        "permissive guest roles and invitation settings, self-service sign-up,\n"
        "and open cross-tenant B2B collaboration defaults.\n"
        "\n"
        "Requires\n"
        "  Graph : Policy.Read.All"
    )

    GUEST_USER_ROLE_ID = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
    RESTRICTED_GUEST_USER_ROLE_ID = "2af84b1e-32c8-42b7-82bc-daa82404023b"
    USER_ROLE_ID = "a0b1b346-4d3e-4e8b-98f8-753987be4970"

    guest_role_names = {
        USER_ROLE_ID: "User",
        GUEST_USER_ROLE_ID: "Guest User",
        RESTRICTED_GUEST_USER_ROLE_ID: "Restricted Guest User",
    }

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.graph_token = None

    def get_graph_headers(self):
        if not self.graph_token:
            self.graph_token = tokenizer.get_graph_token()
        return {
            "Authorization": "Bearer %s" % self.graph_token,
            "Content-Type": "application/json",
        }

    def graph_get_json(self, path):
        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=self.get_graph_headers())
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code != 200:
            error_code = str(((payload.get("error") or {}).get("code")) or "")
            error_message = ((payload.get("error") or {}).get("message")) or "Unknown Graph error"
            raise RuntimeError(
                "Graph request failed with HTTP %s for %s%s%s"
                % (
                    response.status_code,
                    path,
                    ": %s" % error_code if error_code else "",
                    " - %s" % error_message if error_message else "",
                )
            )

        return payload

    def try_graph_get_json(self, path, *, allowed_status_codes=None):
        if allowed_status_codes is None:
            allowed_status_codes = {403, 404}

        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=self.get_graph_headers())
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code == 200:
            return payload

        if response.status_code in allowed_status_codes:
            error_code = str(((payload.get("error") or {}).get("code")) or "")
            console.warn(
                "[!] Skipping %s because Graph returned HTTP %s%s."
                % (
                    path,
                    response.status_code,
                    ": %s" % error_code if error_code else "",
                )
            )
            return None

        error_code = str(((payload.get("error") or {}).get("code")) or "")
        error_message = ((payload.get("error") or {}).get("message")) or "Unknown Graph error"
        raise RuntimeError(
            "Graph request failed with HTTP %s for %s%s%s"
            % (
                response.status_code,
                path,
                ": %s" % error_code if error_code else "",
                " - %s" % error_message if error_message else "",
            )
        )

    def build_tenant_object(self):
        tenant_id = tokenizer.get_current_tenant_id()
        return make_object("tenant", tenant_id, tenant_id)

    def get_guest_role_name(self, role_id):
        return self.guest_role_names.get(role_id, role_id or "Unknown")

    def target_config_is_open(self, target_config, expected_target, expected_type):
        if not isinstance(target_config, dict):
            return False
        if target_config.get("accessType") != "allowed":
            return False
        targets = target_config.get("targets") or []
        return any(
            target.get("target") == expected_target and target.get("targetType") == expected_type
            for target in targets
        )

    def add_default_user_role_findings(self, authorization_policy):
        default_permissions = authorization_policy.get("defaultUserRolePermissions") or {}

        if default_permissions.get("allowedToCreateApps"):
            self.findings.append(make_finding(
                title="Non-admin users can register applications",
                desc=(
                    "The default user role is allowed to create application registrations. "
                    "This increases the risk of ungoverned app registrations and delegated consent abuse."
                ),
                severity="high",
                confidence="high",
                objects=[self.build_tenant_object(), make_object("policy", authorization_policy.get("id"), "authorizationPolicy")],
                evidence=[{
                    "setting": "defaultUserRolePermissions.allowedToCreateApps",
                    "value": True,
                }],
                rec="Disable app registration for the default user role unless there is a strong operational requirement.",
                meta={"scan": self.droplet_name, "category": "weak_user_settings"},
            ))

        if default_permissions.get("allowedToCreateTenants"):
            self.findings.append(make_finding(
                title="Non-admin users can create tenants",
                desc=(
                    "The default user role is allowed to create new tenants. "
                    "This weakens central control over tenant sprawl and delegated administration."
                ),
                severity="medium",
                confidence="high",
                objects=[self.build_tenant_object(), make_object("policy", authorization_policy.get("id"), "authorizationPolicy")],
                evidence=[{
                    "setting": "defaultUserRolePermissions.allowedToCreateTenants",
                    "value": True,
                }],
                rec="Restrict tenant creation to administrators unless the organization intentionally permits tenant self-service.",
                meta={"scan": self.droplet_name, "category": "weak_user_settings"},
            ))

    def add_guest_settings_findings(self, authorization_policy):
        guest_role_id = authorization_policy.get("guestUserRoleId")
        guest_role_name = self.get_guest_role_name(guest_role_id)
        allow_invites_from = authorization_policy.get("allowInvitesFrom")

        if guest_role_id and guest_role_id != self.RESTRICTED_GUEST_USER_ROLE_ID:
            severity = "high" if guest_role_id == self.USER_ROLE_ID else "medium"
            self.findings.append(make_finding(
                title="Guest users are not restricted to the most limited guest role",
                desc=(
                    "Guest users are granted a broader baseline directory role than Restricted Guest User. "
                    "This can expose additional directory data to guest accounts."
                ),
                severity=severity,
                confidence="high",
                objects=[self.build_tenant_object(), make_object("policy", authorization_policy.get("id"), "authorizationPolicy")],
                evidence=[{
                    "setting": "guestUserRoleId",
                    "value": guest_role_id,
                    "resolved_role": guest_role_name,
                }],
                rec="Use the Restricted Guest User role for guests unless broader guest directory access is required.",
                meta={"scan": self.droplet_name, "category": "guest_access"},
            ))

        if allow_invites_from in {"everyone", "adminsGuestInvitersAndAllMembers"}:
            severity = "high" if allow_invites_from == "everyone" else "medium"
            self.findings.append(make_finding(
                title="Guest invitation rights are broadly available",
                desc=(
                    "Guest invitations can be initiated by a broad population of users. "
                    "This increases the chance of uncontrolled B2B guest onboarding."
                ),
                severity=severity,
                confidence="high",
                objects=[self.build_tenant_object(), make_object("policy", authorization_policy.get("id"), "authorizationPolicy")],
                evidence=[{
                    "setting": "allowInvitesFrom",
                    "value": allow_invites_from,
                }],
                rec="Limit guest invitations to admins or designated guest inviters when broad self-service guest onboarding is not required.",
                meta={"scan": self.droplet_name, "category": "guest_access"},
            ))

    def add_authentication_flows_findings(self, authentication_flows_policy):
        if not authentication_flows_policy:
            return

        self_service_sign_up = (authentication_flows_policy.get("selfServiceSignUp") or {}).get("isEnabled")
        if self_service_sign_up:
            self.findings.append(make_finding(
                title="Guest self-service sign-up via user flows is enabled",
                desc=(
                    "External users can self-register through user flows. "
                    "This expands the external identity onboarding surface and should be intentional."
                ),
                severity="medium",
                confidence="high",
                objects=[self.build_tenant_object(), make_object("policy", authentication_flows_policy.get("id"), "authenticationFlowsPolicy")],
                evidence=[{
                    "setting": "selfServiceSignUp.isEnabled",
                    "value": True,
                }],
                rec="Disable guest self-service sign-up unless your applications explicitly rely on this onboarding pattern.",
                meta={"scan": self.droplet_name, "category": "external_id"},
            ))

    def add_cross_tenant_findings(self, cross_tenant_default_policy):
        if not cross_tenant_default_policy:
            return

        inbound = cross_tenant_default_policy.get("b2bCollaborationInbound") or {}
        outbound = cross_tenant_default_policy.get("b2bCollaborationOutbound") or {}

        inbound_open = (
            self.target_config_is_open(inbound.get("usersAndGroups"), "AllUsers", "user")
            and self.target_config_is_open(inbound.get("applications"), "AllApplications", "application")
        )
        outbound_open = (
            self.target_config_is_open(outbound.get("usersAndGroups"), "AllUsers", "user")
            and self.target_config_is_open(outbound.get("applications"), "AllApplications", "application")
        )

        if inbound_open or outbound_open:
            severity = "medium" if inbound_open and outbound_open else "low"
            self.findings.append(make_finding(
                title="Cross-tenant collaboration defaults are broadly open",
                desc=(
                    "The default cross-tenant access policy broadly allows B2B collaboration for all users and applications "
                    "in at least one direction."
                ),
                severity=severity,
                confidence="medium",
                objects=[self.build_tenant_object(), make_object("policy", cross_tenant_default_policy.get("id"), "crossTenantAccessPolicy/default")],
                evidence=[{
                    "is_service_default": cross_tenant_default_policy.get("isServiceDefault"),
                    "b2b_collaboration_inbound_open": inbound_open,
                    "b2b_collaboration_outbound_open": outbound_open,
                    "b2b_collaboration_inbound": inbound,
                    "b2b_collaboration_outbound": outbound,
                }],
                rec="Review whether inbound and outbound B2B collaboration should be restricted to approved users, groups, or applications.",
                meta={"scan": self.droplet_name, "category": "cross_tenant_access"},
            ))

    def run(self):
        self.findings = []
        self.graph_token = None

        status.set_phase("Reading Entra authorization policy")
        authorization_policy = self.graph_get_json("/v1.0/policies/authorizationPolicy")

        status.set_phase("Reading Entra authentication flows policy")
        authentication_flows_policy = self.try_graph_get_json("/v1.0/policies/authenticationFlowsPolicy")

        status.set_phase("Reading cross-tenant access defaults")
        cross_tenant_default_policy = self.try_graph_get_json("/v1.0/policies/crossTenantAccessPolicy/default")

        self.add_default_user_role_findings(authorization_policy)
        self.add_guest_settings_findings(authorization_policy)
        self.add_authentication_flows_findings(authentication_flows_policy)
        self.add_cross_tenant_findings(cross_tenant_default_policy)

        status.set_phase("Writing %s Entra state findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
