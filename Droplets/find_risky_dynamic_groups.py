import json
import util.status as status
import util.tokenizer as tokenizer
import util.http_client as http_client
from Objects.Core import check_pagination, make_finding, make_object, write_findings_to_disk
"""
Droplet to find risky dynamic groups and print them
POC.
This needs recoding for object orientation. Additionally - some garbage functions hanging around, and probably
a bit of optimization needed.
"""
T0_DIRECTORY_ROLES = {
    "Global Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Service Helpdesk Administrator",
    "Helpdesk Administrator",
    "Privileged Role Administrator",
}


class Droplet:
    droplet_name = "Scan: Find risky Dynamic Groups"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Identifies dynamic groups whose membership rules could be abused to\n"
        "gain access to privileged resources. Flags groups with directory role\n"
        "or RBAC assignments where membership is controlled by user-modifiable\n"
        "attributes.\n"
        "\n"
        "Requires\n"
        "  Graph : Group.Read.All, RoleManagement.Read.Directory"
    )

    api_version_parameter = "?api-version=2021-04-01"

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.entra_role_name_cache = {}
        self.app_role_cache = {}
        self.graph_token = None

    def get_graph_headers(self):
        if not self.graph_token:
            self.graph_token = tokenizer.get_graph_token()
        return {
            'Authorization': 'Bearer %s' % self.graph_token,
            'Content-Type': 'application/json',
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

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if 'value' in json_res:
            return check_pagination(self.graph_token, json_res, json_res['value'])
        return []

    def get_all_dynamic_groups(self):
        """
        Queries the Azure API for all dynamic groups and returns them.
        :param token:
        :return:
        """
        status.set_phase("Querying dynamic groups")
        return self.collect_graph_values("/v1.0/groups?$filter=groupTypes/any(i:i eq 'DynamicMembership')")

    def get_role_assignments_for_group(self, group):
        """
        Attempts to grab role assignments for a group. This is fildering against the principalID of the group. (otherwise
        it's going to return every damn principal in the AD.)
        :param token:
        :param group:
        :return:
        """
        return self.collect_graph_values(
            "/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+'%s'" % group
        )

    def get_app_role_assignments_for_group(self, group):
        """
        Queries the group for any app roles assignments for a given group. Looking at the url, it's explanatory.
        :param token:
        :param group:
        :return:
        """
        return self.collect_graph_values("/v1.0/groups/%s/appRoleAssignments" % group)

    def get_entra_role_definition(self, role_definition_id):
        return self.graph_get_json("/v1.0/roleManagement/directory/roleDefinitions/%s" % role_definition_id)

    def get_service_principal(self, service_principal_id):
        return self.graph_get_json("/v1.0/servicePrincipals/%s?$select=id,displayName,appRoles" % service_principal_id)

    def get_entra_role_name(self, role_definition_id):
        if not role_definition_id:
            return ""
        if role_definition_id not in self.entra_role_name_cache:
            try:
                payload = self.get_entra_role_definition(role_definition_id)
                self.entra_role_name_cache[role_definition_id] = payload.get("displayName") or role_definition_id
            except RuntimeError:
                self.entra_role_name_cache[role_definition_id] = role_definition_id
        return self.entra_role_name_cache[role_definition_id]

    def get_app_role_name(self, resource_id, app_role_id):
        cache_key = "%s:%s" % (resource_id, app_role_id)
        if cache_key in self.app_role_cache:
            return self.app_role_cache[cache_key]

        role_name = ""
        if resource_id:
            try:
                payload = self.get_service_principal(resource_id)
                for app_role in payload.get("appRoles", []):
                    if app_role.get("id") == app_role_id:
                        role_name = app_role.get("displayName") or app_role.get("value") or app_role_id
                        break
            except RuntimeError:
                role_name = ""

        if not role_name:
            role_name = app_role_id or ""

        self.app_role_cache[cache_key] = role_name
        return role_name


    def get_risky_groups(self, groups):
        """
        Checks to see if a group has either app role assignments or role assignments and adds that group to a returned list.
        :param token:
        :param groups:
        :return:
        """
        risky_groups = {}
        total_groups = len(groups)
        for index, group in enumerate(groups, start=1):
            status.set_phase("Dynamic group %s/%s: %s" % (
                index,
                total_groups,
                group['displayName'],
            ))

            app_role_assignments = self.get_app_role_assignments_for_group(group['id'])
            entra_role_assignments = self.get_role_assignments_for_group(group['id'])

            if app_role_assignments or entra_role_assignments:
                risky_group = risky_groups.setdefault(group['id'], {
                    "displayName": group['displayName'],
                    "membershipRule": group.get("membershipRule"),
                    "membershipRuleProcessingState": group.get("membershipRuleProcessingState"),
                    "app_role_assignments": [],
                    "entra_role_assignments": [],
                })
                if app_role_assignments:
                    existing_ids = {
                        assignment.get("id") or assignment.get("appRoleId")
                        for assignment in risky_group["app_role_assignments"]
                    }
                    for assignment in app_role_assignments:
                        assignment_id = assignment.get("id") or assignment.get("appRoleId")
                        if assignment_id not in existing_ids:
                            risky_group["app_role_assignments"].append(assignment)
                            existing_ids.add(assignment_id)
                if entra_role_assignments:
                    existing_ids = {
                        assignment.get("id") or assignment.get("roleDefinitionId")
                        for assignment in risky_group["entra_role_assignments"]
                    }
                    for assignment in entra_role_assignments:
                        assignment_id = assignment.get("id") or assignment.get("roleDefinitionId")
                        if assignment_id not in existing_ids:
                            risky_group["entra_role_assignments"].append(assignment)
                            existing_ids.add(assignment_id)

        return risky_groups

    def build_group_object(self, group_id, display_name, membership_rule=None, membership_rule_processing_state=None):
        return make_object(
            "group",
            group_id,
            display_name,
            membership_rule=membership_rule,
            membership_rule_processing_state=membership_rule_processing_state,
        )

    def build_assignment_object(self, assignment, source):
        assignment_id = assignment.get("id") or assignment.get("appRoleId") or assignment.get("roleDefinitionId")
        if source == "entra_role":
            assignment_name = (
                assignment.get("displayName")
                or assignment.get("roleName")
                or self.get_entra_role_name(assignment.get("roleDefinitionId"))
            )
        elif source == "app_role":
            assignment_name = (
                assignment.get("displayName")
                or assignment.get("appRoleName")
                or self.get_app_role_name(assignment.get("resourceId"), assignment.get("appRoleId"))
            )
        else:
            assignment_name = assignment.get("displayName") or assignment.get("appRoleId") or assignment.get("roleDefinitionId")

        return make_object(
            "assignment",
            assignment_id,
            assignment_name,
            source=source,
            role_definition_id=assignment.get("roleDefinitionId"),
            app_role_id=assignment.get("appRoleId"),
            resource_id=assignment.get("resourceId"),
            resource_display_name=assignment.get("resourceDisplayName"),
            raw=assignment,
        )

    def pivot_by_t0_role(self, risky_groups):
        by_role = {}
        for group_id, group_data in risky_groups.items():
            for assignment in group_data.get("entra_role_assignments", []):
                role_name = self.get_entra_role_name(assignment.get("roleDefinitionId"))
                if role_name not in T0_DIRECTORY_ROLES:
                    continue
                entry = by_role.setdefault(role_name, {
                    "role_definition_id": assignment.get("roleDefinitionId"),
                    "groups": {},
                })
                entry["groups"][group_id] = group_data
        return by_role

    def build_t0_role_finding(self, role_name, role_definition_id, groups):
        objects = []
        rows = []
        for group_id, group_data in groups.items():
            objects.append(self.build_group_object(
                group_id,
                group_data["displayName"],
                membership_rule=group_data.get("membershipRule"),
                membership_rule_processing_state=group_data.get("membershipRuleProcessingState"),
            ))
            rows.append({
                "name": group_data["displayName"],
                "dynamic": (group_data.get("membershipRuleProcessingState") or "").lower() != "paused",
            })

        group_count = len(groups)
        return make_finding(
            title="Tier-0 Directory Role Assigned to Dynamic Groups: %s" % role_name,
            desc=(
                "%d dynamic group%s hold%s the %s directory role. An attacker who can satisfy "
                "any group's membership rule gains that Tier-0 privilege."
            ) % (
                group_count,
                "s" if group_count != 1 else "",
                "" if group_count != 1 else "s",
                role_name,
            ),
            severity="high",
            confidence="high",
            objects=objects,
            rec=(
                "Review each group's dynamic membership rule and validate that no user-modifiable "
                "attribute can be abused to satisfy it. Consider replacing dynamic assignment with "
                "direct membership for Tier-0 roles."
            ),
            evidence=[{
                "type": "group_table",
                "columns": ["Name", "Dynamic"],
                "rows": rows,
            }],
            meta={
                "scan": self.droplet_name,
                "finding_type": "t0_role",
                "role_name": role_name,
                "role_definition_id": role_definition_id,
                "group_count": group_count,
            },
        )

    def build_app_role_finding(self, groups):
        objects = []
        rows = []
        for group_id, group_data in groups.items():
            objects.append(self.build_group_object(
                group_id,
                group_data["displayName"],
                membership_rule=group_data.get("membershipRule"),
                membership_rule_processing_state=group_data.get("membershipRuleProcessingState"),
            ))
            for assignment in group_data.get("app_role_assignments", []):
                app_role_name = self.get_app_role_name(
                    assignment.get("resourceId"),
                    assignment.get("appRoleId"),
                )
                rows.append({
                    "group": group_data["displayName"],
                    "app role": app_role_name or assignment.get("appRoleId") or "Unknown",
                    "dynamic": (group_data.get("membershipRuleProcessingState") or "").lower() != "paused",
                })

        group_count = len(groups)
        return make_finding(
            title="Dynamic Groups with App Role Assignments",
            desc=(
                "%d dynamic group%s hold app role assignments. An attacker who can satisfy "
                "any group's membership rule gains those app permissions."
            ) % (group_count, "s" if group_count != 1 else ""),
            severity="medium",
            confidence="high",
            objects=objects,
            rec=(
                "Review each group's dynamic membership rule and app role assignments to ensure "
                "they cannot be exploited to gain unintended application access."
            ),
            evidence=[{
                "type": "group_table",
                "columns": ["Group", "App Role", "Dynamic"],
                "rows": rows,
            }],
            meta={
                "scan": self.droplet_name,
                "finding_type": "app_role",
                "group_count": group_count,
            },
        )

    def build_risky_group_finding(self, group_id, group_data):
        entra_role_assignments = group_data.get("entra_role_assignments", [])
        objects = [
            self.build_group_object(
                group_id,
                group_data["displayName"],
                membership_rule=group_data.get("membershipRule"),
                membership_rule_processing_state=group_data.get("membershipRuleProcessingState"),
            )
        ]
        for assignment in entra_role_assignments:
            objects.append(self.build_assignment_object(assignment, "entra_role"))

        return make_finding(
            title="Dynamic Group with Directory Role Assignment",
            desc="A dynamic group holds one or more Entra ID directory role assignments. An attacker who can satisfy the membership rule gains those directory roles.",
            severity="medium",
            confidence="high",
            objects=objects,
            rec="Review the group's assignments and validate that the dynamic membership rule cannot be abused to gain unintended access.",
            evidence=[{
                "group_id": group_id,
                "group_name": group_data["displayName"],
                "membership_rule": group_data.get("membershipRule"),
                "membership_rule_processing_state": group_data.get("membershipRuleProcessingState"),
                "entra_role_assignments": entra_role_assignments,
            }],
            meta={
                "scan": self.droplet_name,
                "finding_type": "group",
                "group_id": group_id,
            },
        )

    def run(self):
        status.set_phase("Collecting dynamic groups")
        self.findings = []
        self.entra_role_name_cache = {}
        self.app_role_cache = {}
        self.graph_token = None
        dynamic_groups = self.get_all_dynamic_groups()

        if not dynamic_groups:
            risky_groups = {}
        else:
            risky_groups = self.get_risky_groups(dynamic_groups)

        # One finding per T0 directory role
        t0_role_map = self.pivot_by_t0_role(risky_groups)
        for role_name, role_entry in t0_role_map.items():
            self.findings.append(self.build_t0_role_finding(
                role_name,
                role_entry["role_definition_id"],
                role_entry["groups"],
            ))

        t0_group_ids = {gid for role_entry in t0_role_map.values() for gid in role_entry["groups"]}

        # One consolidated finding for all groups with app role assignments
        groups_with_app_roles = {
            gid: gdata for gid, gdata in risky_groups.items()
            if gdata.get("app_role_assignments")
        }
        if groups_with_app_roles:
            self.findings.append(self.build_app_role_finding(groups_with_app_roles))

        # Per-group findings for non-T0 groups with non-T0 entra role assignments
        status.set_phase("Writing %s risky dynamic group findings" % len(risky_groups))
        for group_id, group_data in risky_groups.items():
            if group_id in t0_group_ids:
                continue
            if not group_data.get("entra_role_assignments"):
                continue
            # Strip app roles — those are covered by the consolidated app role finding
            entra_only_data = dict(group_data, app_role_assignments=[])
            self.findings.append(self.build_risky_group_finding(group_id, entra_only_data))

        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
