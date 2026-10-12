import json
import util.console as console
import util.status as status
import util.tokenizer as tokenizer
import util.http_client as http_client
from Objects.Core import check_pagination, choose_severity, make_finding, make_object, write_findings_to_disk

class Droplet:
    droplet_name = "Scan: Find T0 Groups with Entra ID and Azure RBAC roles"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Finds Entra security groups that hold Tier 0 directory roles (e.g.\n"
        "Global Administrator, Privileged Role Administrator) or high-privilege\n"
        "Azure RBAC roles (Owner, Contributor). Expands nested group membership\n"
        "and checks role-assignable groups.\n"
        "\n"
        "Requires\n"
        "  Graph : Group.Read.All, RoleManagement.Read.Directory\n"
        "  ARM   : Reader on subscriptions"
    )


    entra_role_severity = {
        'Global Administrator': 'high',
        'Application Administrator': 'high',
        'Cloud Application Administrator': 'high',
        'Service Helpdesk Administrator': 'high',
        'Helpdesk Administrator': 'high',
        'Privileged Role Administrator': 'high',
        'Security Administrator': 'medium',
        'User Administrator': 'medium',
        'Authentication Administrator': 'medium',
        'Conditional Access Administrator': 'medium',
        'Intune Administrator': 'medium',
        'Exchange Administrator': 'medium',
        'SharePoint Administrator': 'medium',
        'Hybrid Identity Administrator': 'medium',
        'Identity Governance Administrator': 'medium',
    }

    rbac_role_severity = {
        'Owner': 'high',
        'User Access Administrator': 'high',
        'Contributor': 'high',
        'Role Based Access Control Administrator': 'medium',
    }

    # Well-known built-in role definition IDs — identical across all tenants
    # and subscriptions, so we hardcode them to avoid fetching all role
    # definitions for every subscription.
    rbac_t0_role_ids = {
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
        'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168': 'Role Based Access Control Administrator',
    }

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.group_cache = {}
        self._entra_role_cache = {}
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
                    "ARM/RBAC access is unavailable (%s%s). Continuing with Entra-only privileged group results."
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

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if 'value' in json_res:
            return check_pagination(self.graph_token, json_res, json_res['value'])
        return []

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

    def is_t0_role(self, role):
        return role in self.entra_role_severity

    def role_severity(self, role_name, source):
        if source == "entra":
            return self.entra_role_severity.get(role_name, "info")
        if source == "rbac":
            return self.rbac_role_severity.get(role_name, "info")
        return "info"

    def get_all_subscriptions(self):
        return self.collect_arm_values("/subscriptions?api-version=2022-12-01")


    def get_subscription_rbac_roles_assignments_from_role_id(self, subscription_id):
        return self.collect_arm_values(
            "%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" % subscription_id
        )

    def get_groups_via_principal_id(self, principal_id):
        if principal_id not in self.group_cache:
            try:
                self.group_cache[principal_id] = self.graph_get_json("/v1.0/directoryObjects/%s" % principal_id)
            except RuntimeError as exc:
                # Stale role assignments referencing deleted principals return 404.
                # Log and cache None so we skip this principal cleanly.
                if "404" in str(exc):
                    console.debug("[~] Skipping deleted principal %s: %s" % (principal_id, exc))
                    self.group_cache[principal_id] = None
                else:
                    raise
        return self.group_cache[principal_id]

    def get_entra_id_role_by_definition_id(self, role_definition_id):
        if role_definition_id not in self._entra_role_cache:
            self._entra_role_cache[role_definition_id] = self.graph_get_json(
                "/v1.0/roleManagement/directory/roleDefinitions/%s" % role_definition_id
            )
        return self._entra_role_cache[role_definition_id]

    def get_all_role_assignable_groups(self):
        status.set_phase("Fetching role-assignable groups")
        return self.collect_graph_values("/v1.0/groups?$filter=isAssignableToRole eq true")

    def get_role_assignments_for_group(self, group):
        return self.collect_graph_values(
            "/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+'%s'" % group
        )

    def get_entra_role_assigned_groups(self):
        era_groups = {}
        all_role_assignable_groups = self.get_all_role_assignable_groups()
        total_groups = len(all_role_assignable_groups)
        for index, group in enumerate(all_role_assignable_groups, start=1):
            status.set_phase("Role-assignable group %s/%s: %s" % (
                index,
                total_groups,
                group['displayName'],
            ))
            group['entra_role_assignments'] = self.get_role_assignments_for_group(group['id'])
            if group['entra_role_assignments'] and group['id'] not in era_groups:
                era_groups[group['id']] = group

        return era_groups

    def find_t0_groups(self):
        era_groups = self.get_entra_role_assigned_groups()
        t0_groups = {}
        for group_id, group in era_groups.items():
            matching_assignments = []
            for era in group['entra_role_assignments']:
                era['era_displayName'] = self.get_entra_id_role_by_definition_id(era['roleDefinitionId'])['displayName']
                if self.is_t0_role(era['era_displayName']):
                    matching_assignments.append(era)
            if matching_assignments:
                group['entra_role_assignments'] = matching_assignments
                t0_groups[group_id] = group
        return t0_groups

    def build_group_object(self, group):
        return make_object("group", group.get("id"), group.get("displayName"))

    def build_role_object(self, role_name, scope=None, source=None):
        return make_object(
            "role",
            name=role_name,
            scope=scope,
            source=source,
            severity=self.role_severity(role_name, source),
        )

    def build_assignment_object(self, assignment, source, role_name):
        return make_object(
            "assignment",
            assignment.get("id") or assignment.get("roleDefinitionId"),
            role_name,
            source=source,
            principal_id=assignment.get("principalId"),
            role_definition_id=assignment.get("roleDefinitionId"),
            scope=assignment.get("scope") or assignment.get("directoryScopeId"),
            raw=assignment,
        )

    def build_group_finding(self, group, entra_assignments, rbac_assignments):
        all_roles = [assignment["roleName"] for assignment in entra_assignments + rbac_assignments]
        severity = choose_severity(all_roles, {
            **self.entra_role_severity,
            **self.rbac_role_severity,
        })
        role_objects = [
            self.build_role_object(assignment["roleName"], source="entra")
            for assignment in entra_assignments
        ] + [
            self.build_role_object(assignment["roleName"], scope=assignment["scope"], source="rbac")
            for assignment in rbac_assignments
        ]
        assignment_objects = [
            self.build_assignment_object(assignment, "entra", assignment["roleName"])
            for assignment in entra_assignments
        ] + [
            self.build_assignment_object(assignment, "rbac", assignment["roleName"])
            for assignment in rbac_assignments
        ]
        return make_finding(
            title="Privileged Group with Entra ID and/or Azure RBAC Roles",
            desc="A group has one or more privileged Entra ID and/or Azure RBAC role assignments.",
            severity=severity,
            confidence="medium" if self.arm_enrichment_incomplete else "high",
            objects=[self.build_group_object(group)] + role_objects + assignment_objects,
            rec="Review the group membership and remove any Entra ID or Azure RBAC role assignments that are not required.",
            evidence=[{
                "group_id": group.get("id"),
                "group_name": group.get("displayName"),
                "entra_roles": [assignment["roleName"] for assignment in entra_assignments],
                "rbac_roles": [assignment["roleName"] for assignment in rbac_assignments],
                "rbac_scopes": [assignment["scope"] for assignment in rbac_assignments],
                "entra_assignments": entra_assignments,
                "rbac_assignments": rbac_assignments,
                "arm_enrichment_available": not self.arm_enrichment_incomplete,
            }],
            meta={
                "scan": self.droplet_name,
                "sources": [source for source, present in (("entra", bool(entra_assignments)), ("rbac", bool(rbac_assignments))) if present],
                "arm_enrichment_available": not self.arm_enrichment_incomplete,
            },
        )

    def run(self):
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.group_cache = {}
        self._entra_role_cache = {}
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False

        # ----------------- ENTRA SIDE! ------------------

        status.set_phase("Analyzing privileged Entra groups")
        t0_groups = self.find_t0_groups()
        all_risky_groups = {}
        if len(t0_groups)>0:
            for t0_group in t0_groups.values():
                t0_assignments = []
                for era in t0_group['entra_role_assignments']:
                    t0_assignments.append({
                        "id": era.get("id"),
                        "roleName": era['era_displayName'],
                        "roleDefinitionId": era.get("roleDefinitionId"),
                        "principalId": era.get("principalId"),
                        "directoryScopeId": era.get("directoryScopeId"),
                        "raw": era,
                    })
                all_risky_groups[t0_group["id"]] = {
                    "group": t0_group,
                    "entra_assignments": t0_assignments,
                    "rbac_assignments": [],
                }

        # ----------------- RBAC SIDE! ------------------
        subscriptions = self.get_all_subscriptions()
        rbac_groups = {}
        if not self.arm_access_unavailable:
            total_subscriptions = len(subscriptions)
            for index, sub in enumerate(subscriptions, start=1):
                status.set_phase("Subscription %s/%s: %s" % (
                    index,
                    total_subscriptions,
                    sub.get('displayName') or sub.get('subscriptionId') or sub.get('id'),
                ))
                rbac_role_assignments = self.get_subscription_rbac_roles_assignments_from_role_id(subscription_id=sub['id'])

                for rbac_role_assignment in rbac_role_assignments:
                    for t0_rbac_role_id in self.rbac_t0_role_ids.keys():
                        assignment_role_definition_id = str(rbac_role_assignment['properties'].get('roleDefinitionId') or "").split("/")[-1]
                        if (
                            rbac_role_assignment['properties']['principalType'] == 'Group'
                            and t0_rbac_role_id == assignment_role_definition_id
                        ):
                            group = self.get_groups_via_principal_id(rbac_role_assignment['properties']['principalId'])
                            if not isinstance(group, dict) or not group.get('id'):
                                continue
                            if group['id'] not in rbac_groups:
                                rbac_groups[group['id']] = {
                                    "group": group,
                                    "assignments": []
                                }
                            rbac_groups[group['id']]["assignments"].append({
                                "id": rbac_role_assignment.get("id"),
                                "roleName": self.rbac_t0_role_ids[t0_rbac_role_id],
                                "scope": rbac_role_assignment['properties']['scope'],
                                "principalId": rbac_role_assignment['properties'].get('principalId'),
                                "roleDefinitionId": rbac_role_assignment['properties'].get('roleDefinitionId'),
                                "raw": rbac_role_assignment,
                            })
        if len(rbac_groups) > 0:
            for group_id in rbac_groups:
                combined_group = all_risky_groups.setdefault(group_id, {
                    "group": rbac_groups[group_id]["group"],
                    "entra_assignments": [],
                    "rbac_assignments": [],
                })
                combined_group["rbac_assignments"].extend(rbac_groups[group_id]["assignments"])

        for combined_group in all_risky_groups.values():
            self.findings.append(
                self.build_group_finding(
                    combined_group["group"],
                    combined_group["entra_assignments"],
                    combined_group["rbac_assignments"],
                )
            )

        status.set_phase("Writing %s privileged group findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
