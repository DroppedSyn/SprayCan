import json

import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import (
    check_pagination,
    choose_severity,
    load_graph_permissions_from_disk,
    make_finding,
    make_object,
    write_findings_to_disk,
)


class Droplet:
    droplet_name = "Scan: Find risky Agent Identities"
    droplet_path = None
    droplet_type = "scan"
    droplet_description = (
        "Targets AI agent and agentic workload identities. Flags service\n"
        "principals and managed identities holding Graph permissions that\n"
        "Microsoft marks as inappropriate for agent use, or high-privilege\n"
        "Entra directory / Azure RBAC roles.\n"
        "\n"
        "Requires\n"
        "  Graph : Application.Read.All, AppRoleAssignment.Read.All,\n"
        "          RoleManagement.Read.Directory\n"
        "  ARM   : Reader on subscriptions"
    )

    entra_role_severity = {
        "Global Administrator": "high",
        "Application Administrator": "high",
        "Cloud Application Administrator": "high",
        "Service Helpdesk Administrator": "high",
        "Helpdesk Administrator": "high",
        "Privileged Role Administrator": "high",
        "Security Administrator": "medium",
        "User Administrator": "medium",
        "Authentication Administrator": "medium",
        "Conditional Access Administrator": "medium",
        "Intune Administrator": "medium",
        "Exchange Administrator": "medium",
        "SharePoint Administrator": "medium",
        "Hybrid Identity Administrator": "medium",
        "Identity Governance Administrator": "medium",
    }

    rbac_role_severity = {
        "Owner": "high",
        "Contributor": "high",
    }

    risky_graph_permissions = [
        "ReadWrite.Directory",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Directory.AccessAsUser.All",
        "RoleManagement.ReadWrite.Directory",
        "Domain.ReadWrite.All",
        "EntitlementManagement.ReadWrite.All",
        "GroupMember.ReadWrite.All",
    ]

    graph_permissions_blocked_for_agents = {
        "Application.ReadWrite.All",
        "Application.ReadWrite.OwnedBy",
        "AppRoleAssignment.ReadWrite.All",
        "CustomSecAttributeAssignment.ReadWrite.All",
        "CustomSecAttributeDefinition.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All",
        "Directory.AccessAsUser.All",
        "Directory.ReadWrite.All",
        "Directory.Write.Restricted",
        "Domain.ReadWrite.All",
        "EntitlementManagement.ReadWrite.All",
        "Group.ReadWrite.All",
        "Group.Write.Restricted",
        "GroupMember.ReadWrite.All",
        "RoleManagement.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "User-PasswordProfile.ReadWrite.All",
        "User.DeleteRestore.All",
        "User.EnableDisableAccount.All",
        "User.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
    }

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False
        self.role_schedule_access_unavailable = False
        self.role_schedule_access_error = None
        self.role_schedule_access_gap_recorded = False
        self.role_definition_cache = {}

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
            "Authorization": "Bearer %s" % self.arm_token,
            "Content-Type": "application/json",
        }

    def get_graph_headers(self):
        if not self.graph_token:
            self.graph_token = tokenizer.get_graph_token()
        return {
            "Authorization": "Bearer %s" % self.graph_token,
            "Content-Type": "application/json",
        }

    def warn_arm_unavailable(self, message):
        if self.arm_access_warning_emitted:
            return
        console.warn("[!] %s" % message)
        self.arm_access_warning_emitted = True

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
                    "ARM/RBAC access is unavailable (%s%s). Continuing without Azure RBAC agent findings."
                    % (response.status_code, ": %s" % error_code if error_code else "")
                )
            else:
                console.warn("[!] ARM request failed with HTTP %s for %s" % (response.status_code, path))
            return None
        return payload

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if "value" in json_res:
            return check_pagination(self.graph_token, json_res, json_res["value"])
        return []

    def try_collect_graph_values(self, path, access_flag_name=None, error_attr_name=None):
        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=self.get_graph_headers())
        try:
            payload = json.loads(response.content or "{}")
        except ValueError:
            payload = {}

        if response.status_code == 200:
            if "value" in payload:
                return check_pagination(self.graph_token, payload, payload["value"])
            return []

        error_code = str(((payload.get("error") or {}).get("code")) or "")
        error_message = ((payload.get("error") or {}).get("message")) or "Unknown Graph error"
        error_detail = (
            "Graph request failed with HTTP %s for %s%s%s"
            % (
                response.status_code,
                path,
                ": %s" % error_code if error_code else "",
                " - %s" % error_message if error_message else "",
            )
        )
        if access_flag_name:
            setattr(self, access_flag_name, True)
        if error_attr_name:
            setattr(self, error_attr_name, error_detail)
        console.warn("[!] %s. Continuing without this enrichment." % error_detail)
        return []

    def collect_arm_values(self, path):
        json_res = self.arm_get_json(path)
        if json_res is None:
            return []
        if "value" in json_res:
            return check_pagination(self.arm_token, json_res, json_res["value"])
        return []

    def get_all_agent_identities(self):
        return self.collect_graph_values(
            "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
            "?$select=id,displayName,agentIdentityBlueprintId,createdByAppId,createdDateTime,"
            "servicePrincipalType,accountEnabled,disabledByMicrosoftStatus,tags"
        )

    def get_permanent_role_assignments_for_agent(self, agent_id):
        if self.role_schedule_access_unavailable:
            return []
        return self.try_collect_graph_values(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances"
            f"?$filter=principalId%20eq%20'{agent_id}'%20and%20assignmentType%20eq%20'Assigned'",
            access_flag_name="role_schedule_access_unavailable",
            error_attr_name="role_schedule_access_error",
        )

    def get_entra_role_definition(self, role_definition_id):
        if role_definition_id not in self.role_definition_cache:
            self.role_definition_cache[role_definition_id] = self.graph_get_json(
                "/v1.0/roleManagement/directory/roleDefinitions/%s" % role_definition_id
            )
        return self.role_definition_cache[role_definition_id]

    def is_permanent_role_assignment(self, assignment):
        return (
            assignment.get("assignmentType") == "Assigned"
            and assignment.get("endDateTime") is None
        )

    def get_agent_app_role_assignments(self, agent_id):
        return self.collect_graph_values("/v1.0/servicePrincipals/%s/appRoleAssignments" % agent_id)

    def get_all_subscriptions(self):
        return self.collect_arm_values("/subscriptions?api-version=2022-12-01")

    def get_subscription_rbac_role_assignments(self, subscription_id):
        return self.collect_arm_values(
            "%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" % subscription_id
        )

    def get_subscription_rbac_role_definitions(self, subscription_id):
        return self.collect_arm_values(
            "%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01" % subscription_id
        )

    def check_risky_role_permission(self, app_role_value):
        for risky_permission in self.risky_graph_permissions:
            if risky_permission in app_role_value:
                return True
        return False

    def get_permission_severity(self, permission_name):
        if permission_name == "RoleManagement.ReadWrite.Directory":
            return "high"
        return "medium"

    def build_agent_object(self, agent):
        return make_object(
            "agentIdentity",
            agent.get("id"),
            agent.get("displayName"),
            service_principal_type=agent.get("servicePrincipalType"),
            agent_identity_blueprint_id=agent.get("agentIdentityBlueprintId"),
            created_by_app_id=agent.get("createdByAppId"),
            created_date_time=agent.get("createdDateTime"),
            account_enabled=agent.get("accountEnabled"),
            disabled_by_microsoft_status=agent.get("disabledByMicrosoftStatus"),
            tags=agent.get("tags", []),
        )

    def build_role_object(self, role_name, scope=None, source=None):
        severity_map = self.entra_role_severity if source == "entra" else self.rbac_role_severity
        return make_object(
            "role",
            name=role_name,
            scope=scope,
            source=source,
            severity=severity_map.get(role_name, "info"),
        )

    def build_permission_object(self, permission_name, app_role_id=None, blocked_for_agents=False):
        return make_object(
            "permission",
            app_role_id,
            permission_name,
            value=permission_name,
            severity=self.get_permission_severity(permission_name),
            blocked_for_agents=blocked_for_agents,
        )

    def build_subscription_object(self, assignment):
        return make_object(
            "subscription",
            assignment.get("subscription_id"),
            assignment.get("subscription_name"),
            role_name=assignment.get("role_name"),
        )

    def build_assignment_object(self, assignment_id, name, source, **attrs):
        return make_object(
            "assignment",
            assignment_id,
            name,
            source=source,
            **attrs
        )

    def build_entra_role_finding(self, agent, assignments):
        role_names = [assignment["role_name"] for assignment in assignments]
        severity = choose_severity(role_names, self.entra_role_severity, default="medium")
        objects = [self.build_agent_object(agent)]
        for assignment in assignments:
            objects.append(self.build_role_object(assignment["role_name"], scope=assignment["scope"], source="entra"))
            objects.append(self.build_assignment_object(
                assignment["assignment_id"],
                assignment["role_name"],
                "entra",
                role_definition_id=assignment["role_definition_id"],
                scope=assignment["scope"],
            ))

        return make_finding(
            title="Agent identity with permanent privileged Entra role assignment",
            desc="An agent identity has one or more permanent privileged Microsoft Entra role assignments.",
            severity=severity,
            confidence="high",
            objects=objects,
            evidence=[{
                "agent_identity_id": agent.get("id"),
                "agent_identity_name": agent.get("displayName"),
                "agent_identity_blueprint_id": agent.get("agentIdentityBlueprintId"),
                "entra_roles": role_names,
                "entra_role_assignments": assignments,
            }],
            rec="Review whether the agent identity needs permanent Microsoft Entra role assignments and remove any that are not required.",
            meta={
                "scan": self.droplet_name,
                "category": "agent_entra_roles",
                "agent_identity_id": agent.get("id"),
            },
        )

    def build_graph_permission_finding(self, agent, permissions):
        permission_names = [permission["value"] for permission in permissions]
        blocked_permissions = [
            permission["value"]
            for permission in permissions
            if permission["blocked_for_agents"]
        ]
        objects = [self.build_agent_object(agent)]
        for permission in permissions:
            objects.append(self.build_permission_object(
                permission["value"],
                permission.get("appRoleId"),
                blocked_for_agents=permission.get("blocked_for_agents", False),
            ))

        severity = "high" if (
            blocked_permissions
            or any(permission["value"] == "RoleManagement.ReadWrite.Directory" for permission in permissions)
        ) else "medium"

        desc = "An agent identity has one or more privileged Microsoft Graph application permissions."
        if blocked_permissions:
            desc += " At least one assigned permission is currently documented by Microsoft as blocked for agents."

        return make_finding(
            title="Agent identity with risky Microsoft Graph application permissions",
            desc=desc,
            severity=severity,
            confidence="high",
            objects=objects,
            evidence=[{
                "agent_identity_id": agent.get("id"),
                "agent_identity_name": agent.get("displayName"),
                "agent_identity_blueprint_id": agent.get("agentIdentityBlueprintId"),
                "graph_permissions": permission_names,
                "blocked_for_agents_permissions": blocked_permissions,
                "app_role_assignments": permissions,
            }],
            rec="Review the agent's Microsoft Graph application permissions and remove anything beyond the minimum required access.",
            meta={
                "scan": self.droplet_name,
                "category": "agent_graph_permissions",
                "agent_identity_id": agent.get("id"),
            },
        )

    def build_rbac_finding(self, agent, assignments):
        role_names = [assignment["role_name"] for assignment in assignments]
        severity = choose_severity(role_names, self.rbac_role_severity, default="medium")
        objects = [self.build_agent_object(agent)]
        for assignment in assignments:
            objects.append(self.build_role_object(assignment["role_name"], scope=assignment["scope"], source="rbac"))
            objects.append(self.build_subscription_object(assignment))
            objects.append(self.build_assignment_object(
                assignment["assignment_id"],
                assignment["role_name"],
                "rbac",
                scope=assignment["scope"],
                subscription_id=assignment["subscription_id"],
                subscription_name=assignment["subscription_name"],
                role_definition_id=assignment["role_definition_id"],
            ))

        return make_finding(
            title="Agent identity with privileged Azure RBAC assignment",
            desc="An agent identity has Owner or Contributor on one or more subscriptions.",
            severity=severity,
            confidence="medium" if self.arm_enrichment_incomplete else "high",
            objects=objects,
            evidence=[{
                "agent_identity_id": agent.get("id"),
                "agent_identity_name": agent.get("displayName"),
                "agent_identity_blueprint_id": agent.get("agentIdentityBlueprintId"),
                "subscription_roles": assignments,
                "arm_enrichment_available": not self.arm_enrichment_incomplete,
            }],
            rec="Review whether the agent identity needs subscription-level RBAC and reduce the assigned scope or role where possible.",
            meta={
                "scan": self.droplet_name,
                "category": "agent_rbac_roles",
                "agent_identity_id": agent.get("id"),
                "arm_enrichment_available": not self.arm_enrichment_incomplete,
            },
        )

    def build_entra_role_access_gap_finding(self):
        return make_finding(
            title="Agent identity Entra role assignments could not be assessed",
            desc=(
                "Microsoft Graph denied or failed the role assignment schedule API used to identify permanent "
                "privileged Entra role assignments on agent identities. Graph permission and Azure RBAC checks "
                "can still complete, but the Entra role portion is incomplete."
            ),
            severity="medium",
            confidence="medium",
            objects=[],
            evidence=[{
                "assessment": "agent_identity_permanent_entra_role_assignments",
                "role_assignment_schedule_read_available": False,
                "reason": self.role_schedule_access_error,
            }],
            rec=(
                "Grant the reader identity a supported role-management Graph scope, such as "
                "RoleAssignmentSchedule.Read.Directory or RoleManagement.Read.Directory, then rerun the scan."
            ),
            meta={
                "scan": self.droplet_name,
                "category": "agent_entra_role_access",
            },
        )

    def analyze_entra_role_assignments(self, agents):
        findings = []
        total_agents = len(agents)
        for index, agent in enumerate(agents, start=1):
            if self.role_schedule_access_unavailable:
                break

            status.set_phase("Agent roles %s/%s: %s" % (index, total_agents, agent.get("displayName") or agent.get("id")))
            role_assignments = self.get_permanent_role_assignments_for_agent(agent["id"])
            if self.role_schedule_access_unavailable:
                break

            matching_assignments = []
            for assignment in role_assignments:
                if not self.is_permanent_role_assignment(assignment):
                    continue
                role_definition_id = assignment.get("roleDefinitionId")
                if not role_definition_id:
                    continue
                role_name = self.get_entra_role_definition(role_definition_id).get("displayName")
                if role_name in self.entra_role_severity:
                    matching_assignments.append({
                        "assignment_id": assignment.get("id"),
                        "role_name": role_name,
                        "role_definition_id": role_definition_id,
                        "scope": assignment.get("directoryScopeId") or "/",
                        "app_scope_id": assignment.get("appScopeId"),
                        "assignment_type": assignment.get("assignmentType"),
                        "member_type": assignment.get("memberType"),
                        "start_date_time": assignment.get("startDateTime"),
                        "end_date_time": assignment.get("endDateTime"),
                        "role_assignment_origin_id": assignment.get("roleAssignmentOriginId"),
                        "role_assignment_schedule_id": assignment.get("roleAssignmentScheduleId"),
                    })
            if matching_assignments:
                findings.append(self.build_entra_role_finding(agent, matching_assignments))

        if self.role_schedule_access_unavailable and not self.role_schedule_access_gap_recorded:
            findings.append(self.build_entra_role_access_gap_finding())
            self.role_schedule_access_gap_recorded = True
        return findings

    def analyze_graph_permissions(self, agents):
        findings = []
        status.set_phase("Loading Graph permission catalog")
        graph_permissions = load_graph_permissions_from_disk()
        risky_permissions_by_id = {
            app_role.get("id"): app_role.get("value")
            for app_role in graph_permissions.get("appRoles", [])
            if self.check_risky_role_permission(app_role.get("value", ""))
        }

        total_agents = len(agents)
        for index, agent in enumerate(agents, start=1):
            status.set_phase("Agent Graph permissions %s/%s: %s" % (index, total_agents, agent.get("displayName") or agent.get("id")))
            app_role_assignments = self.get_agent_app_role_assignments(agent["id"])
            risky_permissions = []
            for assignment in app_role_assignments:
                app_role_value = risky_permissions_by_id.get(assignment.get("appRoleId"))
                if not app_role_value:
                    continue
                risky_permissions.append({
                    "assignment_id": assignment.get("id"),
                    "appRoleId": assignment.get("appRoleId"),
                    "resourceId": assignment.get("resourceId"),
                    "resourceDisplayName": assignment.get("resourceDisplayName"),
                    "value": app_role_value,
                    "blocked_for_agents": app_role_value in self.graph_permissions_blocked_for_agents,
                })
            if risky_permissions:
                findings.append(self.build_graph_permission_finding(agent, risky_permissions))
        return findings

    def analyze_rbac_assignments(self, agents):
        findings = []
        agent_by_id = {agent["id"]: agent for agent in agents}
        target_agent_ids = set(agent_by_id.keys())
        subscriptions = self.get_all_subscriptions()
        agent_assignments = {}

        total_subscriptions = len(subscriptions)
        for index, subscription in enumerate(subscriptions, start=1):
            if self.arm_access_unavailable:
                break

            status.set_phase("Agent RBAC %s/%s: %s" % (
                index,
                total_subscriptions,
                subscription.get("displayName") or subscription.get("subscriptionId") or subscription.get("id"),
            ))
            role_assignments = self.get_subscription_rbac_role_assignments(subscription["id"])
            role_definitions = self.get_subscription_rbac_role_definitions(subscription["id"])
            target_role_ids = {
                role_definition.get("name"): (role_definition.get("properties") or {}).get("roleName")
                for role_definition in role_definitions
                if role_definition.get("properties", {}).get("roleName") in self.rbac_role_severity
            }

            for role_assignment in role_assignments:
                properties = role_assignment.get("properties") or {}
                principal_id = properties.get("principalId")
                if principal_id not in target_agent_ids:
                    continue

                role_definition_id = str(properties.get("roleDefinitionId") or "").split("/")[-1]
                role_name = target_role_ids.get(role_definition_id)
                if not role_name:
                    continue

                agent_assignments.setdefault(principal_id, []).append({
                    "assignment_id": role_assignment.get("id"),
                    "role_name": role_name,
                    "role_definition_id": properties.get("roleDefinitionId"),
                    "scope": properties.get("scope"),
                    "subscription_id": subscription.get("subscriptionId"),
                    "subscription_name": subscription.get("displayName"),
                    "principal_type": properties.get("principalType"),
                })

        for agent_id, assignments in agent_assignments.items():
            findings.append(self.build_rbac_finding(agent_by_id[agent_id], assignments))
        return findings

    def run(self):
        self.findings = []
        self.arm_token = None
        self.graph_token = None
        self.arm_access_unavailable = False
        self.arm_access_warning_emitted = False
        self.arm_enrichment_incomplete = False
        self.role_schedule_access_unavailable = False
        self.role_schedule_access_error = None
        self.role_schedule_access_gap_recorded = False
        self.role_definition_cache = {}

        status.set_phase("Collecting agent identities")
        agents = self.get_all_agent_identities()

        status.set_phase("Analyzing %s agent identities" % len(agents))
        self.findings.extend(self.analyze_entra_role_assignments(agents))
        self.findings.extend(self.analyze_graph_permissions(agents))
        self.findings.extend(self.analyze_rbac_assignments(agents))

        status.set_phase("Writing %s risky agent identity findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)
        return self.findings
