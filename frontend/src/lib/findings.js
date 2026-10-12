export function normalizeFindings(payload) {
  const findings = Array.isArray(payload) ? payload : payload && Array.isArray(payload.findings) ? payload.findings : [];
  return Array.from(new Map(findings.filter(Boolean).map((finding) => [finding.id, finding])).values());
}

export function countBySeverity(findings) {
  return findings.reduce((acc, finding) => {
    const severity = finding.severity || "info";
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});
}

export function formatScanName(finding) {
  return finding?.meta?.scan || "Unknown scan";
}

export function shortId(value, size = 8) {
  if (!value) {
    return "";
  }
  return value.length <= size ? value : value.slice(0, size);
}

export function getObjectsByType(finding, type) {
  return (finding?.objects || []).filter((obj) => obj.type === type);
}

export function getPrimaryObject(finding, type) {
  return getObjectsByType(finding, type)[0] || null;
}

export function getFindingSearchText(finding) {
  return [
    finding.title,
    finding.desc,
    finding.severity,
    finding.confidence,
    formatScanName(finding),
    ...(finding.objects || []).flatMap((obj) => [obj.type, obj.name, obj.id, obj.scope, obj.source, obj.value]),
    ...(finding.evidence || []).map((item) => JSON.stringify(item)),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function summarizeFinding(finding) {
  const group = getPrimaryObject(finding, "group");
  const app = getPrimaryObject(finding, "application");
  const sp = getPrimaryObject(finding, "servicePrincipal");
  const functionApp = getPrimaryObject(finding, "functionApp");
  const logicApp = getPrimaryObject(finding, "logicApp");
  const trigger = getPrimaryObject(finding, "trigger");
  const roles = getObjectsByType(finding, "role");
  const permissions = getObjectsByType(finding, "permission");
  const assignments = getObjectsByType(finding, "assignment");
  const logicApps = getObjectsByType(finding, "logicApp");
  const evidence = finding.evidence?.[0] || {};
  const scan = formatScanName(finding);

  if (scan.includes("T0 Groups")) {
    const sources = finding.meta?.sources || [];
    const scopes = roles.map((role) => role.scope).filter(Boolean);
    return {
      eyebrow: group?.name || "Privileged group",
      headline: roles.map((role) => role.name).filter(Boolean).join(", ") || "Privileged role assignment",
      meta: [...sources, ...scopes].join(" • "),
    };
  }

  if (scan.includes("Service Principals")) {
    return {
      eyebrow: sp?.name || "Service principal",
      headline: permissions.map((permission) => permission.name).filter(Boolean).join(", ") || "Risky permission",
      meta: logicApps.length ? `Attached to ${logicApps.length} logic app${logicApps.length === 1 ? "" : "s"}` : "Standalone service principal",
    };
  }

  if (scan.includes("Dynamic Groups")) {
    const findingType = finding.meta?.finding_type;
    if (findingType === "t0_role" || finding.meta?.role_name) {
      const roleName = finding.meta?.role_name;
      const groupCount = finding.meta?.group_count ?? getObjectsByType(finding, "group").length;
      return {
        eyebrow: roleName || "Tier-0 role",
        headline: `${groupCount} dynamic group${groupCount === 1 ? "" : "s"}`,
        meta: "Tier-0 role exposure",
      };
    }
    if (findingType === "app_role") {
      const groupCount = finding.meta?.group_count ?? getObjectsByType(finding, "group").length;
      return {
        eyebrow: "App role assignments",
        headline: `${groupCount} dynamic group${groupCount === 1 ? "" : "s"}`,
        meta: "App role exposure",
      };
    }
    return {
      eyebrow: group?.name || "Dynamic group",
      headline: assignments.length
        ? `${assignments.length} role assignment${assignments.length === 1 ? "" : "s"}`
        : "Directory role exposure",
      meta: "Assignment exposure",
    };
  }

  if (scan.includes("Dangling app-reg")) {
    const urls = (finding.evidence || []).map((item) => item.redirect_uri).filter(Boolean);
    return {
      eyebrow: app?.name || "Application",
      fields: [
        { label: "App Name", value: app?.name || "Unknown application" },
        { label: "App ID", value: app?.id || "Unknown" },
        { label: "URLs", value: urls.join("\n") || "Dangling redirect URI" },
      ],
    };
  }

  if (scan.includes("Logic and Function App Review")) {
    const resource = functionApp || logicApp;
    if (!resource && !evidence.resource_name) {
      return {
        eyebrow: finding.title,
        headline: finding.meta?.affected_count != null
          ? "%s app%s affected".replace("%s", finding.meta.affected_count).replace("%s", finding.meta.affected_count === 1 ? "" : "s")
          : finding.desc,
        meta: scan,
      };
    }
    return {
      eyebrow: resource?.name || evidence.resource_name,
      headline: trigger?.name || evidence.trigger_name || finding.title,
      meta: [
        evidence.platform || resource?.type,
        evidence.auth_mode,
        evidence.client_certificate_mode,
      ].filter(Boolean).join(" • ") || scan,
    };
  }

  if (scan.includes("NSG Inbound")) {
    const nsg = getPrimaryObject(finding, "networkSecurityGroup");
    const ruleEntries = (finding.evidence || []).slice(1);
    const topRule = ruleEntries.find((e) => e.classification_severity === "high") || ruleEntries[0];
    return {
      eyebrow: nsg?.name || finding.title,
      headline: topRule?.rule_summary || topRule?.rule_name || finding.desc,
      meta: [
        evidence.matched_rule_count != null
          ? `${evidence.matched_rule_count} rule${evidence.matched_rule_count === 1 ? "" : "s"}`
          : null,
        evidence.region,
      ].filter(Boolean).join(" • "),
    };
  }

  return {
    eyebrow: finding.title,
    headline: finding.desc,
    meta: scan,
  };
}

export function detailFacts(finding) {
  const group = getPrimaryObject(finding, "group");
  const app = getPrimaryObject(finding, "application");
  const sp = getPrimaryObject(finding, "servicePrincipal");
  const functionApp = getPrimaryObject(finding, "functionApp");
  const logicApp = getPrimaryObject(finding, "logicApp");
  const trigger = getPrimaryObject(finding, "trigger");
  const roles = getObjectsByType(finding, "role");
  const permissions = getObjectsByType(finding, "permission");
  const assignments = getObjectsByType(finding, "assignment");
  const logicApps = getObjectsByType(finding, "logicApp");
  const evidence = finding.evidence?.[0] || {};
  const scan = formatScanName(finding);

  if (scan.includes("T0 Groups")) {
    const entraAssignmentCount = assignments.filter((assignment) => assignment.source === "entra").length;
    const rbacAssignmentCount = assignments.filter((assignment) => assignment.source === "rbac").length;
    return [
      ["Group", group?.name || "Unknown"],
      ["Sources", (finding.meta?.sources || []).join(", ") || "Unknown"],
      ["Roles", roles.map((role) => role.name).join(", ") || "None"],
      ["Entra assignments", String(entraAssignmentCount)],
      ["RBAC assignments", String(rbacAssignmentCount)],
      ["Scopes", evidence.rbac_scopes?.join(", ") || roles.map((role) => role.scope).filter(Boolean).join(", ") || "Tenant-wide"],
    ];
  }

  if (scan.includes("Service Principals")) {
    return [
      ["Service principal", sp?.name || "Unknown"],
      ["Permissions", permissions.map((permission) => permission.name).join(", ") || "None"],
      ["Managed identities", logicApps.map((logicApp) => logicApp.name).join(", ") || "None"],
      ["Risk driver", permissions.some((permission) => permission.name === "RoleManagement.ReadWrite.Directory") ? "Directory role management" : "Privileged application permissions"],
    ];
  }

  if (scan.includes("Dynamic Groups")) {
    const findingType = finding.meta?.finding_type;
    if (findingType === "t0_role" || finding.meta?.role_name) {
      const groups = getObjectsByType(finding, "group");
      return [
        ["Role", finding.meta?.role_name || "Unknown"],
        ["Affected groups", String(groups.length)],
        ["Role definition ID", finding.meta?.role_definition_id || "Unknown"],
      ];
    }
    if (findingType === "app_role") {
      const groups = getObjectsByType(finding, "group");
      const rows = finding.evidence?.[0]?.rows || [];
      return [
        ["Affected groups", String(groups.length)],
        ["App role assignments", String(rows.length)],
      ];
    }
    return [
      ["Group", group?.name || "Unknown"],
      ["Directory role assignments", String(assignments.filter((assignment) => assignment.source === "entra_role").length)],
    ];
  }

  if (scan.includes("Dangling app-reg")) {
    return [
      ["Application", app?.name || "Unknown"],
      ["Redirect URI", evidence.redirect_uri || "Unknown"],
      ["Host", evidence.resolved_domain || "Unknown"],
      ["Resolution", evidence.resolution_status || "Unknown"],
    ];
  }

  if (scan.includes("Logic and Function App Review")) {
    if (evidence.type === "trigger_table") {
      const rows = evidence.rows || [];
      const highCount = rows.filter(r => r.row_severity === "high").length;
      const lowCount = rows.filter(r => r.row_severity === "low").length;
      const subCount = new Set(rows.map(r => r.subscription).filter(Boolean)).size;
      return [
        ["Triggers", String(rows.length)],
        ["High severity", String(highCount)],
        ["Low severity", String(lowCount)],
        ["Subscriptions", String(subCount)],
      ];
    }
    const resource = functionApp || logicApp;
    return [
      ["Resource", resource?.name || evidence.resource_name || "Unknown"],
      ["Platform", evidence.platform || resource?.type || "Unknown"],
      ["Trigger", trigger?.name || evidence.trigger_name || "Not recorded"],
      ["Auth mode", evidence.auth_mode || "Unknown"],
      ["HTTPS only", evidence.https_only == null ? "N/A" : String(evidence.https_only)],
      ["Min TLS", evidence.minimum_inbound_tls_version || "N/A"],
      ["HTTP version", evidence.http_version || "N/A"],
      ["Client cert mode", evidence.client_certificate_mode || "N/A"],
    ];
  }

  if (scan.includes("NSG Inbound")) {
    const nsg = getPrimaryObject(finding, "networkSecurityGroup");
    return [
      ["NSG", nsg?.name || "Unknown"],
      ["Region", evidence.region || "Unknown"],
      ["Subscription", evidence.subscription_name || "Unknown"],
      ["Rules matched", String(evidence.matched_rule_count || 0)],
      ["Attached subnets", String(evidence.attached_subnet_count || 0)],
      ["Attached NICs", String(evidence.attached_nic_count || 0)],
    ];
  }

  return [
    ["Scan", scan],
    ["Objects", String((finding.objects || []).length)],
    ["Evidence entries", String((finding.evidence || []).length)],
    ["Confidence", finding.confidence || "Unknown"],
  ];
}
