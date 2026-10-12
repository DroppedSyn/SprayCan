import json
import util.console as console
import util.status as status
import util.tokenizer as tokenizer
import util.http_client as http_client
from Objects.Core import check_pagination, load_graph_permissions_from_disk, make_finding, make_object, write_findings_to_disk
"""
Droplet to find risky SPs that require further followp.
POC-ish?
"""

class LogicApp():
    def __init__(self, name, id):
        self.name = name
        self.id = id
        self.user_assigned_identities = {}
        self.system_assigned_identity = None

class Droplet:
    droplet_name = "Scan: Find risky Service Principals"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Enumerates all service principals and flags those holding privileged\n"
        "Graph API application permissions (e.g. AppRoleAssignment.ReadWrite.All,\n"
        "RoleManagement.ReadWrite.Directory). Where ARM is available, correlates\n"
        "flagged SPs with Logic App managed identities for additional context.\n"
        "\n"
        "Requires\n"
        "  Graph : Application.Read.All, AppRoleAssignment.Read.All\n"
        "  ARM   : Reader on subscriptions (Logic App correlation only)"
    )

    api_version_parameter = "?api-version=2021-04-01"

    # Risky Roles Array. These are the roles we look for.
    # NOTE: you need RoleManagement.ReadWrite.Directory to manage group assignment for role-assignable groups!

    risky_roles = ['ReadWrite.Directory',
                   'Application.ReadWrite.All',
                   'AppRoleAssignment.ReadWrite.All',
                   'Directory.ReadWrite.All',
                   'Directory.AccessAsUser.All',
                   'RoleManagement.ReadWrite.Directory',
                   'Domain.ReadWrite.All',
                   'EntitlementManagement.ReadWrite.All',
                   'GroupMember.ReadWrite.All']

    role_severity = {
        'RoleManagement.ReadWrite.Directory': 'high',
        'ReadWrite.Directory': 'medium',
        'Application.ReadWrite.All': 'medium',
        'AppRoleAssignment.ReadWrite.All': 'high',
        'Directory.ReadWrite.All': 'medium',
        'Directory.AccessAsUser.All': 'medium',
        'Domain.ReadWrite.All': 'medium',
        'EntitlementManagement.ReadWrite.All': 'medium',
        'GroupMember.ReadWrite.All': 'medium',
    }

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False

    def get_arm_headers(self):
        if self.arm_access_unavailable:
            return None
        if not self.arm_token:
            try:
                self.arm_token = tokenizer.get_arm_token()
            except Exception as exc:
                self.arm_access_unavailable = True
                self.arm_enrichment_incomplete = True
                self.warn_arm_unavailable("Could not acquire an ARM token: %s" % exc)
                return None
        return {
            'Authorization': 'Bearer %s' % self.arm_token,
            'Content-Type': 'application/json',
        }

    def get_graph_headers(self):
        if not self.graph_token:
            self.graph_token = tokenizer.get_graph_token()
        return {
            'Authorization': 'Bearer %s' % self.graph_token,
            'Content-Type': 'application/json',
        }

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
                self.warn_arm_unavailable(
                    "ARM access is unavailable (%s%s). Continuing without Logic App correlation."
                    % (response.status_code, ": %s" % error_code if error_code else "")
                )
            else:
                console.warn("[!] ARM request failed with HTTP %s for %s" % (response.status_code, path))
            return None
        return payload

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

    def collect_arm_values(self, path):
        json_res = self.arm_get_json(path)
        if json_res is None:
            return []
        if 'value' in json_res:
            return check_pagination(self.arm_token, json_res, json_res['value'])
        return []

    def warn_arm_unavailable(self, message):
        if self.arm_access_warning_emitted:
            return
        console.warn("[!] %s" % message)
        self.arm_access_warning_emitted = True

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if 'value' in json_res:
            return check_pagination(self.graph_token, json_res, json_res['value'])
        return []

    def get_all_subscriptions(self):
        return self.collect_arm_values("/subscriptions?api-version=2022-12-01")

    def get_all_logic_apps(self, subscription):
        return self.collect_arm_values("%s/providers/Microsoft.Logic/workflows?api-version=2019-05-01" % subscription)

    def get_logic_apps_permissions(self):
        status.set_phase("Collecting Logic Apps")
        subscriptions = self.get_all_subscriptions()
        if self.arm_access_unavailable:
            return []

        subscription_logic_apps = []

        total_subscriptions = len(subscriptions)
        for index, subscription in enumerate(subscriptions, start=1):
            status.set_phase("Logic Apps %s/%s: %s" % (index, total_subscriptions, subscription['displayName']))
            r_logic_apps = self.get_all_logic_apps(subscription['id'])

            if len(r_logic_apps) > 0:
                subscription_logic_apps.append(r_logic_apps)

        logic_apps = []
        for subscription in subscription_logic_apps:
            for logic_app in subscription:
                #print("Logic App: %s " % logic_app)
                #Check if theres an identity. If not, dont event store it.
                if 'identity' in logic_app:
                    l_app = LogicApp(logic_app['name'], logic_app['id'])
                    if 'UserAssigned' in logic_app['identity']['type']:
                        user_assigned_identities = {}
                        for user_assigned_identity in logic_app['identity']['userAssignedIdentities']:
                            user_assigned_identities[user_assigned_identity] = logic_app['identity']['userAssignedIdentities'][user_assigned_identity]
                        l_app.user_assigned_identities = user_assigned_identities
                    if 'SystemAssigned' in logic_app['identity']['type']:
                        l_app.system_assigned_identity = logic_app['identity']["principalId"]
                    logic_apps.append(l_app)

        return logic_apps

    def get_all_service_principals(self):
        return self.collect_graph_values("/v1.0/servicePrincipals")

    def get_service_principal_appRoleAssignments(self, id):
        return self.collect_graph_values("/v1.0/servicePrincipals/%s/appRoleAssignments" % id)

    def check_risky_roles(self, app_role):
        """
        Takes in a value and checks against the risky approle list. Should really populate the list with risky approles
        or alternatively populate it somewhere else.
        :param app_role:
        :return:
        """
        result = False
        #self.risky_roles.append('Mail.Read')  # For debug. This role is everywhere.
        for risky_role in self.risky_roles:
            if risky_role in app_role:
                result = True
        return result

    def get_role_severity(self, role_name):
        return self.role_severity.get(role_name, "medium")

    def build_service_principal_object(self, sp):
        return make_object(
            "servicePrincipal",
            sp.get("id"),
            sp.get("displayName") or sp.get("appDisplayName"),
        )

    def build_permission_object(self, app_role_value, app_role_id=None):
        return make_object(
            "permission",
            app_role_id,
            app_role_value,
            value=app_role_value,
            severity=self.get_role_severity(app_role_value),
        )

    def build_logic_app_object(self, logic_app):
        return make_object("logicApp", logic_app.id, logic_app.name)

    def get_user_assigned_identity_principal_ids(self, logic_app):
        principal_ids = []
        for identity_payload in (logic_app.user_assigned_identities or {}).values():
            if not isinstance(identity_payload, dict):
                continue
            principal_id = identity_payload.get("principalId")
            if principal_id:
                principal_ids.append(principal_id)
        return principal_ids

    def build_finding(self, sp, permissions, logic_apps):
        objects = [self.build_service_principal_object(sp)]
        for permission in permissions:
            objects.append(self.build_permission_object(permission["value"], permission.get("appRoleId")))
        for logic_app in logic_apps:
            objects.append(self.build_logic_app_object(logic_app))

        evidence = [{
            "service_principal_id": sp.get("id"),
            "service_principal_name": sp.get("displayName") or sp.get("appDisplayName"),
            "permissions": [permission["value"] for permission in permissions],
            "managed_identities": [logic_app.name for logic_app in logic_apps],
            "arm_enrichment_available": not self.arm_enrichment_incomplete,
        }]

        severity = "high" if any(permission["value"] == "RoleManagement.ReadWrite.Directory" for permission in permissions) else "medium"

        return make_finding(
            title="Service Principal with risky permissions",
            desc="A service principal has one or more privileged application permissions.",
            severity=severity,
            confidence="medium" if self.arm_enrichment_incomplete else "high",
            objects=objects,
            rec="Review the assigned application permissions and remove anything that is not required.",
            evidence=evidence,
            meta={
                "scan": self.droplet_name,
                "service_principal_id": sp.get("id"),
                "arm_enrichment_available": not self.arm_enrichment_incomplete,
            },
        )

    def analyze_permissions(self, sps):
        findings = []
        logic_apps = self.get_logic_apps_permissions()
        json_graph_permissions = load_graph_permissions_from_disk()
        risky_permissions_by_id = {
            app_role.get("id"): app_role.get("value")
            for app_role in json_graph_permissions.get('appRoles', [])
            if self.check_risky_roles(app_role.get("value", ""))
        }
        logic_apps_by_principal_id = {}
        for logic_app in logic_apps:
            if logic_app.system_assigned_identity:
                logic_apps_by_principal_id.setdefault(logic_app.system_assigned_identity, []).append(logic_app)
            for principal_id in self.get_user_assigned_identity_principal_ids(logic_app):
                logic_apps_by_principal_id.setdefault(principal_id, []).append(logic_app)

        total_service_principals = len(sps)
        for current_index, sp in enumerate(sps, start=1):
            if current_index % 100 == 0:
                status.set_phase("Analyzed %s/%s service principals" % (current_index, total_service_principals))
            try:
                app_role_assignments = self.get_service_principal_appRoleAssignments(id=sp['id'])
            except Exception as exc:
                console.warn("[!] Skipping SP %s/%s (%s): %s" % (current_index, total_service_principals, sp.get('id'), exc))
                continue

            try:
                risky_permissions = []
                for role_permission in app_role_assignments:
                    app_role_value = risky_permissions_by_id.get(role_permission.get('appRoleId'))
                    if app_role_value:
                        risky_permissions.append({
                            "value": app_role_value,
                            "appRoleId": role_permission.get('appRoleId'),
                        })

                if risky_permissions:
                    matched_logic_apps = logic_apps_by_principal_id.get(sp['id'], [])
                    finding = self.build_finding(sp, risky_permissions, matched_logic_apps)
                    findings.append(finding)
            except Exception as exc:
                console.warn("[!] Skipping SP %s/%s (%s) during analysis: %s" % (current_index, total_service_principals, sp.get('id'), exc))
        return findings

    def run(self):
        status.set_phase("Collecting service principals")
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False

        returned_service_principals = self.get_all_service_principals()

        status.set_phase("Analyzing %s service principals" % len(returned_service_principals))
        self.findings = self.analyze_permissions(returned_service_principals)

        status.set_phase("Writing %s risky service principal findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
