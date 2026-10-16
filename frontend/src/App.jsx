import { useEffect, useMemo, useState } from "react";
import FilesPane from "./components/FilesPane.jsx";
import FindingDetailPane from "./components/FindingDetailPane.jsx";
import FindingsPane from "./components/FindingsPane.jsx";
import ScanPage from "./components/ScanPage.jsx";
import SeverityFilter from "./components/SeverityFilter.jsx";
import TenantSelector from "./components/TenantSelector.jsx";
import TopologyDetailPane from "./components/TopologyDetailPane.jsx";
import Toolbar from "./components/Toolbar.jsx";
import {
  formatDateKey,
  formatFileLabel,
  formatScanType,
  formatTenantLabel,
  getActiveFileMeta,
  normalizeFiles,
} from "./lib/files.js";
import {
  countBySeverity,
  detailFacts,
  getFindingSearchText,
  formatScanName,
  normalizeFindings,
  shortId,
  summarizeFinding,
} from "./lib/findings.js";
import {
  buildNetworkInventory,
  buildScopedNetworkGraph,
  findNetworkInventoryKey,
  getNetworkSearchText,
  groupNetworkInventory,
  normalizeNetworkModel,
  pluralize,
  summarizeNetworkRouteTables,
  summarizeNetworkFocus,
  summarizeNetworkSecurityGroups,
} from "./lib/topology.js";

const severityOrder = ["high", "medium", "low", "info"];
const themeStorageKey = "spraycan.canvas.theme";

function getStoredTheme() {
  try {
    return window.localStorage.getItem(themeStorageKey) || "light";
  } catch {
    return "light";
  }
}

export default function App() {
  const [files, setFiles] = useState([]);
  const [activeFile, setActiveFile] = useState("");
  const [loadedPayload, setLoadedPayload] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [selectedNetworkKey, setSelectedNetworkKey] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState("");
  const [tenants, setTenants] = useState([]);
  const [activeTenantId, setActiveTenantId] = useState("");
  const [expandedFindings, setExpandedFindings] = useState({});
  const [theme, setTheme] = useState(() => getStoredTheme());
  const [activePane, setActivePane] = useState("files");
  const [authStatus, setAuthStatus] = useState({
    authMode: "none",
    isAuthenticated: false,
    tenantId: null,
    tokenType: null,
  });
  const [networkFocus, setNetworkFocus] = useState([]);
  const [networkView, setNetworkView] = useState("shape");
  const [expandedTopologyGroups, setExpandedTopologyGroups] = useState({});

  function getTenantDisplayName(tenantId) {
    const tenant = tenants.find((t) => t.id === tenantId);
    return (tenant && tenant.name) || formatTenantLabel(tenantId);
  }

  async function loadFindingsFile(fileName, nextFiles = files) {
    setStatus("loading");
    setError("");

    const res = await fetch(`/api/findings/${encodeURIComponent(fileName)}`);
    if (!res.ok) {
      throw new Error("Failed to load selected findings file");
    }

    const payload = await res.json();
    const loadedFindings = normalizeFindings(payload.findings);
    const active = nextFiles.find((file) => file.name === payload.file);

    setLoadedPayload(payload.findings);
    setActiveFile(payload.file);
    setFindings(loadedFindings);
    setSelectedId(loadedFindings[0]?.id || "");
    const networkModel = normalizeNetworkModel(payload.findings);
    if (networkModel) {
      const inventory = buildNetworkInventory(networkModel);
      setSelectedNetworkKey(inventory[0]?.key || "");
    }

    if (loadedFindings[0]?.id) {
      setExpandedFindings((current) => ({
        ...current,
        [loadedFindings[0].id]: true,
      }));
    }

    setStatus("ready");
  }

  async function refreshFiles() {
    try {
      const res = await fetch("/api/files");
      if (res.ok) {
        const payload = await res.json();
        setFiles(normalizeFiles(payload));
      }
    } catch {
      // server not reachable — ignore
    }
  }

  function openScanPane() {
    setActivePane("scan");
  }

  async function refreshAuthStatus(tenantId = activeTenantId) {
    if (!tenantId) return;
    try {
      const res = await fetch(`/api/auth/status?tenantId=${encodeURIComponent(tenantId)}`);
      if (res.ok) setAuthStatus(await res.json());
    } catch {
      // server not yet ready — ignore
    }
  }

  async function selectTenant(tenantId, currentFiles = files) {
    if (!tenantId) return;
    setActiveTenantId(tenantId);
    setFindings([]);
    setActiveFile("");
    setSelectedId("");
    setLoadedPayload([]);

    try {
      const authRes = await fetch(`/api/auth/status?tenantId=${encodeURIComponent(tenantId)}`);
      if (authRes.ok) setAuthStatus(await authRes.json());
    } catch { /* ignore */ }

    const tenantFiles = currentFiles.filter((f) => f.tenantId === tenantId);
    if (tenantFiles.length > 0) {
      const latest = tenantFiles.reduce((a, b) => ((a.epochMs || 0) > (b.epochMs || 0) ? a : b));
      try {
        await loadFindingsFile(latest.name, currentFiles);
      } catch {
        setStatus("ready");
      }
    } else {
      setStatus("ready");
    }
  }

  async function registerTenant(tenantId, name) {
    try {
      const res = await fetch("/api/tenants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: tenantId, name }),
      });
      if (res.ok) {
        const data = await res.json();
        setTenants(data.tenants);
        await selectTenant(tenantId, files);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function renameTenant(tenantId, name) {
    try {
      const res = await fetch(`/api/tenants/${encodeURIComponent(tenantId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantName: name }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.tenants) setTenants(data.tenants);
        setFiles(normalizeFiles(data.files));
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteTenant(tenantId) {
    try {
      const res = await fetch(`/api/tenants/${encodeURIComponent(tenantId)}`, { method: "DELETE" });
      if (!res.ok) return;
      const data = await res.json();
      setTenants(data.tenants);

      // Still present (e.g. reappeared as "discovered" because it has files) — leave the
      // current view alone. Only switch away if it's gone from the list entirely.
      const stillExists = data.tenants.some((t) => t.id === tenantId);
      if (tenantId === activeTenantId && !stillExists) {
        const next = data.tenants[0];
        if (next) {
          await selectTenant(next.id, files);
        } else {
          setActiveTenantId("");
          setFindings([]);
          setActiveFile("");
          setSelectedId("");
        }
      }
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    async function bootstrap() {
      try {
        const [filesRes, tenantsRes] = await Promise.all([
          fetch("/api/files"),
          fetch("/api/tenants"),
        ]);

        if (!filesRes.ok) throw new Error("Failed to load files");

        const filesPayload = await filesRes.json();
        const tenantsPayload = tenantsRes.ok ? await tenantsRes.json() : [];
        const normalizedFiles = normalizeFiles(filesPayload);

        setFiles(normalizedFiles);
        setTenants(tenantsPayload);
        setError("");

        // Start with nothing open; the user picks a tenant and scan themselves.
        setStatus("ready");
      } catch (err) {
        setError(err.message);
        setStatus("error");
      }
    }

    bootstrap();
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem(themeStorageKey, theme);
  }, [theme]);

  async function loadFile(fileName) {
    try {
      await loadFindingsFile(fileName);
      setActivePane("files");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }

  async function deleteFile(fileName) {
    try {
      const res = await fetch(`/api/findings/${encodeURIComponent(fileName)}?tenantId=${encodeURIComponent(activeTenantId)}`, { method: "DELETE" });
      if (!res.ok) return;
      const data = await res.json();
      const nextFiles = normalizeFiles(data.files);
      setFiles(nextFiles);

      if (activeFile === fileName) {
        // Deleted the currently loaded file — load the next most recent for this tenant or clear
        const tenantFiles = nextFiles.filter((f) => f.tenantId === activeTenantId);
        if (tenantFiles.length > 0) {
          const next = tenantFiles.reduce((a, b) => ((a.epochMs || 0) > (b.epochMs || 0) ? a : b));
          await loadFindingsFile(next.name, nextFiles).catch(() => {});
        } else {
          setActiveFile("");
          setFindings([]);
          setSelectedId("");
          setLoadedPayload([]);
          setStatus("ready");
        }
      }
    } catch {
      // server unreachable — ignore
    }
  }

  const filteredFindings = findings.filter((finding) => {
    const matchesSeverity = severity === "all" || finding.severity === severity;
    const matchesQuery = !query || getFindingSearchText(finding).includes(query.toLowerCase());
    return matchesSeverity && matchesQuery;
  });

  const selectedFinding =
    filteredFindings.find((finding) => finding.id === selectedId) || filteredFindings[0] || null;
  const networkModel = useMemo(() => normalizeNetworkModel(loadedPayload), [loadedPayload]);
  const networkInventory = useMemo(() => buildNetworkInventory(networkModel), [networkModel]);
  const filteredNetworkInventory = useMemo(
    () =>
      networkInventory.filter((item) => !query || getNetworkSearchText(item).includes(query.toLowerCase())),
    [networkInventory, query],
  );
  const groupedNetworkInventory = useMemo(
    () => groupNetworkInventory(filteredNetworkInventory),
    [filteredNetworkInventory],
  );
  const selectedNetworkItem =
    filteredNetworkInventory.find((item) => item.key === selectedNetworkKey) || filteredNetworkInventory[0] || null;
  const scopedNetworkGraph = useMemo(
    () => buildScopedNetworkGraph(networkModel, selectedNetworkItem, networkView),
    [networkModel, selectedNetworkItem, networkView],
  );
  const activeGraphNodeId =
    selectedNetworkItem?.data?.id || selectedNetworkItem?.data?.network_interface_id || selectedNetworkItem?.data?.name || "";

  const counts = countBySeverity(findings);
  const networkFocusSummary = summarizeNetworkFocus(networkModel);
  const networkSecurityGroups = useMemo(
    () => summarizeNetworkSecurityGroups(networkModel),
    [networkModel],
  );
  const networkRouteTables = useMemo(
    () => summarizeNetworkRouteTables(networkModel),
    [networkModel],
  );
  const activeFileMeta = getActiveFileMeta(files, activeFile);

  useEffect(() => {
    if (!selectedFinding && filteredFindings[0]?.id) {
      setSelectedId(filteredFindings[0].id);
      setExpandedFindings((current) => ({
        ...current,
        [filteredFindings[0].id]: true,
      }));
    }
  }, [filteredFindings, selectedFinding]);

  useEffect(() => {
    if (networkModel && !selectedNetworkItem && filteredNetworkInventory[0]?.key) {
      setSelectedNetworkKey(filteredNetworkInventory[0].key);
    }
  }, [networkModel, filteredNetworkInventory, selectedNetworkItem]);

  useEffect(() => {
    if (!groupedNetworkInventory.length) {
      return;
    }
    setExpandedTopologyGroups((current) => {
      const next = { ...current };
      for (const group of groupedNetworkInventory) {
        if (!(group.kind in next)) {
          next[group.kind] = false;
        }
      }
      return next;
    });
  }, [groupedNetworkInventory]);

  function toggleFinding(findingId) {
    setExpandedFindings((current) => ({
      ...current,
      [findingId]: !current[findingId],
    }));
  }

  function toggleTheme() {
    setTheme((current) => (current === "dark" ? "light" : "dark"));
  }

  function toggleNetworkFocus(kind) {
    setNetworkFocus((current) =>
      current.includes(kind) ? current.filter((item) => item !== kind) : [...current, kind],
    );
  }

  function toggleTopologyGroup(kind) {
    setExpandedTopologyGroups((current) => ({
      ...current,
      [kind]: !current[kind],
    }));
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <p className="eyebrow">SprayCan</p>
          <h1>
            <span className="brand-mark" aria-hidden="true">{` .-.
 |#|
 |_|
 / \\`}</span>
            <em>Canvas</em>
          </h1>
          <p className="brand-tagline">Shake well before use.</p>
        </div>

        <TenantSelector
          tenants={tenants}
          activeTenantId={activeTenantId}
          onSelectTenant={(id) => selectTenant(id)}
          onRenameTenant={renameTenant}
          onRegisterTenant={registerTenant}
          onDeleteTenant={deleteTenant}
        />

        {activeTenantId && (
          <>
            <button
              type="button"
              className={`scan-launch-btn${activePane === "scan" ? " active" : ""}`}
              onClick={() => setActivePane(activePane === "scan" ? "files" : "scan")}
            >
              {activePane === "scan" ? "Close Scans" : "Scan"}
            </button>
            <FilesPane
              files={files}
              activeTenantId={activeTenantId}
              activeFile={activeFile}
              loadFile={loadFile}
              deleteFile={deleteFile}
              openScanPane={openScanPane}
            />
            {!networkModel && (
              <SeverityFilter
                severityOrder={severityOrder}
                severity={severity}
                counts={counts}
                findingsCount={findings.length}
                setSeverity={setSeverity}
              />
            )}
          </>
        )}
      </aside>

      <main className="content">
        {activePane === "scan" && activeTenantId ? (
          <ScanPage
            activeTenantId={activeTenantId}
            authStatus={authStatus}
            setAuthStatus={setAuthStatus}
            refreshAuthStatus={refreshAuthStatus}
            refreshFiles={refreshFiles}
          />
        ) : (
          <>
            <Toolbar
              activeFile={activeFile}
              activeFileMeta={activeFileMeta}
              networkModel={networkModel}
              query={query}
              theme={theme}
              formatFileLabel={formatFileLabel}
              formatDateKey={formatDateKey}
              getTenantDisplayName={getTenantDisplayName}
              setQuery={setQuery}
              toggleTheme={toggleTheme}
            />

            {status === "error" ? <div className="empty-state">{error}</div> : null}

            <div className="workspace">
              <FindingsPane
                activeFile={activeFile}
                networkModel={networkModel}
                status={status}
                filteredFindings={filteredFindings}
                filteredNetworkInventory={filteredNetworkInventory}
                groupedNetworkInventory={groupedNetworkInventory}
                expandedTopologyGroups={expandedTopologyGroups}
                selectedNetworkItem={selectedNetworkItem}
                setSelectedNetworkKey={setSelectedNetworkKey}
                toggleTopologyGroup={toggleTopologyGroup}
                summarizeFinding={summarizeFinding}
                expandedFindings={expandedFindings}
                selectedFinding={selectedFinding}
                setSelectedId={setSelectedId}
                toggleFinding={toggleFinding}
                shortId={shortId}
                formatScanName={formatScanName}
              />

              <section className="detail-pane">
                {networkModel ? (
                  <TopologyDetailPane
                    selectedNetworkItem={selectedNetworkItem}
                    networkSecurityGroups={networkSecurityGroups}
                    networkRouteTables={networkRouteTables}
                    networkFocusSummary={networkFocusSummary}
                    networkView={networkView}
                    setNetworkView={setNetworkView}
                    networkFocus={networkFocus}
                    toggleNetworkFocus={toggleNetworkFocus}
                    scopedNetworkGraph={scopedNetworkGraph}
                    activeGraphNodeId={activeGraphNodeId}
                    theme={theme}
                    filteredNetworkInventory={filteredNetworkInventory}
                    findNetworkInventoryKey={findNetworkInventoryKey}
                    setSelectedNetworkKey={setSelectedNetworkKey}
                    pluralize={pluralize}
                  />
                ) : (
                  <FindingDetailPane
                    selectedFinding={selectedFinding}
                    detailFacts={detailFacts}
                  />
                )}
              </section>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
