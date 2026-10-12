import { formatScanName, getObjectsByType } from "../lib/findings.js";
import ExportCsvButton from "./ExportCsvButton.jsx";

const TRIGGER_TABLE_COLUMNS = [
  { label: "Severity", key: "row_severity" },
  { label: "App Name", key: "app_name" },
  { label: "Function / Trigger", key: "trigger_name" },
  { label: "Subscription", key: "subscription" },
  { label: "Auth Mode", key: "auth_mode" },
  { label: "Notes", key: "notes" },
];

function badPctColor(pct) {
  const hue = Math.max(0, Math.round(120 - pct * 1.2));
  return `hsl(${hue}, 42%, var(--pct-l, 40%))`;
}

function renderMetrics(finding) {
  const metrics = finding.meta?.metrics;
  const csvPaths = finding.meta?.csv_paths || [];
  if (!metrics?.length) return null;

  return (
    <div className="metrics-section">
      {metrics.map((cat, ci) => (
        <div key={ci} className="metrics-category">
          <p className="metrics-category-label">
            {cat.category}
            <span className="metrics-total"> ({cat.total})</span>
          </p>
          {cat.checks.map((check, ki) => {
            const pct = cat.total ? Math.round((check.bad / check.total) * 100) : 0;
            const color = check.info
              ? (pct === 0 ? "var(--muted)" : "var(--info)")
              : badPctColor(pct);
            return (
              <div key={ki} className="metrics-check-row">
                <span className="metrics-check-label">{check.label}</span>
                <span className="metrics-check-count">{check.bad} / {check.total}</span>
                <span className="metrics-check-pct" style={{ color }}>{pct}%</span>
              </div>
            );
          })}
        </div>
      ))}
      {csvPaths.length > 0 && (
        <div className="metrics-downloads">
          <div className="metrics-downloads-header">
            <p className="metrics-downloads-label">Download CSVs</p>
            <button
              type="button"
              className="metrics-download-all"
              onClick={() => {
                csvPaths.forEach((p, i) => {
                  setTimeout(() => {
                    const a = document.createElement("a");
                    a.href = `/api/csv?path=${encodeURIComponent(p)}`;
                    a.download = p.split("/").pop();
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                  }, i * 120);
                });
              }}
            >
              Download all
            </button>
          </div>
          <div className="metrics-downloads-list">
            {csvPaths.map((p, i) => (
              <a
                key={i}
                href={`/api/csv?path=${encodeURIComponent(p)}`}
                download
                className="metrics-csv-link"
              >
                {p.split("/").pop()}
              </a>
            ))}
          </div>
        </div>
      )}
      {finding.desc && (
        <details className="metrics-pastable">
          <summary>Pastable summary</summary>
          <pre className="metrics-pastable-pre">{finding.desc}</pre>
        </details>
      )}
    </div>
  );
}

function formatAssignmentSourceLabel(source) {
  if (source === "entra" || source === "entra_role") {
    return "entra";
  }
  if (source === "rbac") {
    return "rbac";
  }
  if (source === "app_role") {
    return "app";
  }
  return source || "assignment";
}

function renderTriggerTable(rows, filename) {
  if (!rows || !rows.length) return null;
  return (
    <div className="table-with-export">
      <ExportCsvButton
        columns={TRIGGER_TABLE_COLUMNS.map((col) => col.label)}
        rows={rows}
        getCell={(row, label) => row[TRIGGER_TABLE_COLUMNS.find((col) => col.label === label).key]}
        filename={filename}
      />
      <table className="trigger-table">
        <thead>
          <tr>
            {TRIGGER_TABLE_COLUMNS.map((col) => <th key={col.key}>{col.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              <td><span className={`badge ${row.row_severity}`}>{row.row_severity}</span></td>
              <td>{row.app_name || "—"}</td>
              <td>{row.trigger_name || "—"}</td>
              <td>{row.subscription || "—"}</td>
              <td>{row.auth_mode || "—"}</td>
              <td>{row.notes || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function hasTableEvidence(finding) {
  return (finding.evidence || []).some(
    (item) => item.type === "app_table" || item.type === "trigger_table" || item.type === "group_table"
  );
}

function renderGroupTable(columns, rows, filename) {
  if (!columns || !rows || !rows.length) return null;
  return (
    <div className="table-with-export">
      <ExportCsvButton
        columns={columns}
        rows={rows}
        getCell={(row, col) => row[col.toLowerCase()]}
        filename={filename}
      />
      <table className="trigger-table">
        <thead>
          <tr>
            {columns.map((col) => <th key={col}>{col}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((col) => {
                const val = row[col.toLowerCase()];
                if (typeof val === "boolean") {
                  return (
                    <td key={col} style={{ textAlign: "center" }}>
                      <input type="checkbox" checked={val} readOnly />
                    </td>
                  );
                }
                return <td key={col}>{val != null ? String(val) : "—"}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function renderAppTable(columns, rows, filename) {
  if (!columns || !rows || !rows.length) return null;
  return (
    <div className="table-with-export">
      <ExportCsvButton columns={columns} rows={rows} filename={filename} />
      <table className="trigger-table">
        <thead>
          <tr>
            {columns.map((col) => <th key={col}>{col}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((col) => (
                <td key={col}>{row[col] != null ? String(row[col]) : "—"}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function renderKeyValueTable(rows) {
  const visibleRows = rows.filter(([, value]) => value != null && value !== "");
  if (!visibleRows.length) {
    return null;
  }

  return (
    <div className="detail-kv-table" role="table">
      {visibleRows.map(([label, value]) => (
        <div key={label} className="detail-kv-row" role="row">
          <span className="detail-kv-label" role="cell">{label}</span>
          <span className="detail-kv-value" role="cell">{String(value)}</span>
        </div>
      ))}
    </div>
  );
}

function renderRoleList(finding) {
  const roles = getObjectsByType(finding, "role");
  if (!roles.length) {
    return null;
  }
  return (
    <div className="detail-block">
      <h3>Privileged Roles</h3>
      <div className="tag-list">
        {roles.map((role, index) => (
          <div key={`${role.name}-${index}`} className="object-pill">
            <span className={`badge ${role.severity || finding.severity}`}>{role.severity || finding.severity}</span>
            <div>
              <strong>{role.name}</strong>
              <p>{role.source === "rbac" ? role.scope || "Scope not recorded" : "Entra directory role"}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function renderPermissionList(finding) {
  const permissions = getObjectsByType(finding, "permission");
  if (!permissions.length) {
    return null;
  }
  return (
    <div className="detail-block">
      <h3>Risky Permissions</h3>
      <div className="tag-list">
        {permissions.map((permission, index) => (
          <div key={`${permission.id || permission.name}-${index}`} className="object-pill">
            <span className={`badge ${permission.severity || finding.severity}`}>{permission.severity || finding.severity}</span>
            <div>
              <strong>{permission.name}</strong>
              <p>{permission.value || "Application permission"}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function renderAssignmentList(finding) {
  const assignments = getObjectsByType(finding, "assignment");
  if (!assignments.length) {
    return null;
  }
  return (
    <div className="detail-block">
      <h3>Assignments</h3>
      <div className="tag-list">
        {assignments.map((assignment, index) => (
          <div key={`${assignment.id || assignment.name}-${index}`} className="object-pill">
            <span className="badge info">{formatAssignmentSourceLabel(assignment.source)}</span>
            <div>
              <strong>{assignment.name || assignment.id || "Assignment"}</strong>
              <p>{assignment.id || "Raw assignment present in evidence"}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function renderAttachedResources(finding) {
  const logicApps = getObjectsByType(finding, "logicApp");
  if (!logicApps.length) {
    return null;
  }
  return (
    <div className="detail-block">
      <h3>Attached Resources</h3>
      <div className="tag-list">
        {logicApps.map((logicApp, index) => (
          <div key={`${logicApp.id}-${index}`} className="object-pill">
            <span className="badge info">logic app</span>
            <div>
              <strong>{logicApp.name}</strong>
              <p>{logicApp.id}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function renderEvidence(finding) {
  const scan = formatScanName(finding);
  const evidence = finding.evidence?.[0] || {};

  if (scan.includes("Dangling app-reg")) {
    return (
      <div className="detail-item">
        <strong>Redirect target</strong>
        {renderKeyValueTable([
          ["Redirect URI", evidence.redirect_uri || "Unknown redirect URI"],
          ["Host", evidence.resolved_domain || "Unknown"],
          ["Status", evidence.resolution_status || "Unknown"],
        ])}
      </div>
    );
  }

  if (scan.includes("T0 Groups")) {
    return (
      <div className="detail-item">
        <strong>{evidence.group_name || "Group"}</strong>
        {renderKeyValueTable([
          ["Entra roles", (evidence.entra_roles || []).join(", ") || "None"],
          ["RBAC roles", (evidence.rbac_roles || []).join(", ") || "None"],
          ["RBAC scopes", evidence.rbac_scopes?.join(", ") || ""],
        ])}
      </div>
    );
  }

  if (scan.includes("Service Principals")) {
    return (
      <div className="detail-item">
        <strong>{evidence.service_principal_name || "Service principal"}</strong>
        {renderKeyValueTable([
          ["Permissions", (evidence.permissions || []).join(", ") || "None"],
          ["Managed identities", (evidence.managed_identities || []).join(", ") || "None"],
        ])}
      </div>
    );
  }

  if (scan.includes("Dynamic Groups")) {
    return (finding.evidence || []).map((item, index) => {
      if (item.type === "group_table") {
        return (
          <div key={index} className="detail-item">
            {renderGroupTable(item.columns, item.rows, `${finding.title}_${index}`)}
          </div>
        );
      }
      return (
        <div key={index} className="detail-item">
          <strong>{item.group_name || "Dynamic group"}</strong>
          {renderKeyValueTable([
            ["Directory roles", String((item.entra_role_assignments || []).length)],
            ["Membership rule", item.membership_rule || ""],
          ])}
        </div>
      );
    });
  }

  if (scan.includes("NSG Inbound")) {
    const ruleEntries = (finding.evidence || []).slice(1);
    if (!ruleEntries.length) {
      return <div className="detail-item"><p>No rule details recorded.</p></div>;
    }
    return ruleEntries.map((item, index) => (
      <div key={index} className="detail-item">
        <strong>{item.rule_summary || item.rule_name || "Rule"}</strong>
        {renderKeyValueTable([
          ["Rule name", item.rule_name || ""],
          ["Priority", item.priority != null ? String(item.priority) : ""],
          ["Protocol", item.protocol || ""],
          ["Source", item.source_scope === "any" ? "ANY" : (item.source_prefixes || []).join(", ") || "ANY"],
          ["Destination", item.destination_scope === "any" ? "ANY" : (item.destination_prefixes || []).join(", ") || "ANY"],
          ["Ports", item.port_scope === "any" ? "ANY" : (item.destination_ports || []).join(", ") || "ANY"],
          ["Severity", item.classification_severity || ""],
        ])}
      </div>
    ));
  }

  if (scan.includes("Logic and Function App Review")) {
    return (finding.evidence || []).map((item, index) => {
      if (item.type === "app_table") {
        return (
          <div key={index} className="detail-item">
            {renderAppTable(item.columns, item.rows, `${finding.title}_${index}`)}
          </div>
        );
      }

      if (item.type === "trigger_table") {
        return (
          <div key={index} className="detail-item">
            {renderTriggerTable(item.rows, `${finding.title}_${index}`)}
          </div>
        );
      }

      if (item.pattern) {
        return (
          <div key={index} className="detail-item">
            <strong>{item.pattern}</strong>
            {renderKeyValueTable([
              ["Source", item.source || "Unknown"],
              ["Path", item.path || ""],
              ["Snippet", item.snippet || "No snippet recorded"],
            ])}
          </div>
        );
      }

      return (
        <div key={index} className="detail-item">
          <strong>{item.resource_name || "Logic/Function app"}</strong>
          {renderKeyValueTable([
            ["Platform", item.platform || "Unknown"],
            ["Subscription", item.subscription_name || ""],
            ["Resource group", item.resource_group || ""],
            ["Region", item.region || ""],
            ["Trigger", item.trigger_name || ""],
            ["Trigger type", item.trigger_type || ""],
            ["Trigger kind", item.trigger_kind || ""],
            ["Auth mode", item.auth_mode || ""],
            ["Client cert mode", item.client_certificate_mode || ""],
            ["Callback URL", item.callback_url || ""],
            ["Config path", item.config_path || ""],
          ])}
        </div>
      );
    });
  }

  if (scan.includes("Resource Review")) {
    return (finding.evidence || []).map((item, index) => {
      const offenders = item.offenders || [];
      return (
        <div key={index} className="detail-item">
          <strong>
            <span className={`badge ${item.severity}`}>{item.severity}</span> {item.check}
          </strong>
          {renderKeyValueTable([["Affected", `${item.bad} / ${item.total}`]])}
          <details className="metrics-pastable">
            <summary>{offenders.length} offending resource{offenders.length === 1 ? "" : "s"}</summary>
            <pre className="metrics-pastable-pre">{offenders.join("\n")}</pre>
          </details>
        </div>
      );
    });
  }

  if (scan.includes("Front Door Origin Exposure")) {
    return (finding.evidence || []).map((item, index) => (
      <div key={index} className="detail-item">
        {item.type === "app_table"
          ? renderAppTable(item.columns, item.rows, `${finding.title}_${index}`)
          : renderKeyValueTable([["Raw", JSON.stringify(item)]])}
      </div>
    ));
  }

  return (finding.evidence || []).map((item, index) => (
    <div key={index} className="detail-item">
      {renderKeyValueTable([["Raw", JSON.stringify(item)]])}
    </div>
  ));
}

function renderObjectsFallback(finding) {
  const genericObjects = (finding.objects || []).filter(
    (obj) => !["group", "role", "servicePrincipal", "permission", "logicApp", "functionApp", "trigger", "assignment", "application"].includes(obj.type),
  );

  if (!genericObjects.length) {
    return null;
  }

  return (
    <div className="detail-block">
      <h3>Other Objects</h3>
      {genericObjects.map((obj, index) => (
        <div key={`${obj.id || obj.name}-${index}`} className="detail-item">
          <strong>{obj.name || obj.type}</strong>
          <pre>{JSON.stringify(obj, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
}

export default function FindingDetailPane({
  selectedFinding,
  detailFacts,
}) {
  if (!selectedFinding) {
    return <div className="empty-state">Select a finding to inspect it.</div>;
  }

  return (
    <>
      <div className="detail-header">
        <span className={`badge ${selectedFinding.severity}`}>{selectedFinding.severity}</span>
        <span className="mono long-id" title={selectedFinding.id}>{selectedFinding.id}</span>
      </div>
      <h2>{selectedFinding.title}</h2>
      {selectedFinding.meta?.metrics
        ? renderMetrics(selectedFinding)
        : <p className="detail-copy">{selectedFinding.desc}</p>
      }
      <p className="detail-scan" title={formatScanName(selectedFinding)}>
        {formatScanName(selectedFinding)}
      </p>

      <div className="facts-grid">
        {detailFacts(selectedFinding).map(([label, value]) => (
          <div key={label} className="fact-card">
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      {renderRoleList(selectedFinding)}
      {renderPermissionList(selectedFinding)}
      {renderAssignmentList(selectedFinding)}
      {renderAttachedResources(selectedFinding)}

      {hasTableEvidence(selectedFinding) ? (
        <>
          <div className="detail-block">
            <h3>Recommendations (Beta)</h3>
            <div className="detail-item detail-item-compact">
              <p>{selectedFinding.rec || "No recommendation recorded."}</p>
            </div>
          </div>
          <div className="detail-block">
            <h3>Evidence</h3>
            {renderEvidence(selectedFinding)}
          </div>
        </>
      ) : (
        <div className="detail-grid">
          <div className="detail-block">
            <h3>Evidence</h3>
            {renderEvidence(selectedFinding)}
          </div>
          <div className="detail-block">
            <h3>Recommendations (Beta)</h3>
            <div className="detail-item detail-item-compact">
              <p>{selectedFinding.rec || "No recommendation recorded."}</p>
            </div>
          </div>
        </div>
      )}

      <div className="detail-grid">
        <div className="detail-block">
          <h3>Primary Objects</h3>
          {(selectedFinding.objects || [])
            .filter((obj) => ["group", "servicePrincipal", "application", "logicApp", "functionApp", "trigger"].includes(obj.type))
            .map((obj, index) => (
              <div key={`${obj.id || obj.name}-${index}`} className="detail-item">
                <strong>{obj.name || obj.type}</strong>
                {renderKeyValueTable([
                  ["Type", obj.type],
                  ["ID", obj.id || "Not recorded"],
                  ["Name", obj.name || ""],
                  ["Trigger type", obj.trigger_type || ""],
                  ["Trigger kind", obj.trigger_kind || ""],
                  ["Auth mode", obj.auth_mode || ""],
                  ["Client cert mode", obj.client_cert_mode || ""],
                ])}
              </div>
            ))}
        </div>

        {!selectedFinding.meta?.metrics && (
          <div className="detail-block">
            <h3>Meta</h3>
            <div className="detail-item">
              <pre>{JSON.stringify(selectedFinding.meta || {}, null, 2)}</pre>
            </div>
          </div>
        )}
      </div>

      {selectedFinding.meta?.paste_output && (
        <details className="metrics-pastable">
          <summary>Pastable output</summary>
          <pre className="metrics-pastable-pre">{selectedFinding.meta.paste_output}</pre>
        </details>
      )}

      {renderObjectsFallback(selectedFinding)}
    </>
  );
}
