import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import {
  DndContext,
  DragOverlay,
  PointerSensor,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import AuthSection from "./AuthSection.jsx";

function cleanName(name) {
  return name.replace(/^[^:]+:\s*/, "");
}

function extractError(data, fallback) {
  const d = data?.detail;
  if (!d) return fallback;
  if (typeof d === "string") return d;
  if (d.detail) return d.detail;
  if (d.error) return d.error;
  return JSON.stringify(d);
}

// Registry for droplet-scoped settings that should only appear on the Scan page while their
// droplet is actually queued (rather than cluttering every scan run with unrelated toggles).
// To add a new one:
//   1. In util/settings.py: add get_<x>()/set_<x>() backed by set_setting/get_setting.
//   2. In server.py: add GET/POST /api/settings/<slug> returning/accepting {"enabled": bool} —
//      same shape as every entry below, so no frontend change beyond this array is needed.
//   3. Add an entry here. scanName must exactly match the droplet's `droplet_name`.
const SCAN_TOGGLES = [
  {
    scanName: "Scan: Front Door Origin Exposure",
    stateKey: "frontDoorProbePayload",
    settingsPath: "/api/settings/front-door-probe-payload",
    label: "Front Door probe: send test payload (risk of WAF/IDS flagging)",
    tooltip:
      "Sends an XSS-style test string directly at each discovered Front Door origin and its " +
      "public domain, to confirm WAF bypass. Off by default — this is live traffic against " +
      "production infrastructure and is more likely than a plain reachability check to trip a " +
      "WAF/IDS and get the scanning IP flagged or blocked.",
  },
];

function ScanQueueCard({ entry, isActive, isCompleted, isCancelling, onRemove, onFocus, disabled }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } =
    useSortable({ id: entry.uid, data: { source: "queue" }, disabled });

  const style = {
    transform: isDragging ? undefined : CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.35 : 1,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`scan-queue-card${isActive ? " active" : isCompleted ? " completed" : ""}`}
      onClick={() => onFocus(entry)}
    >
      <span
        className="scan-queue-drag-handle"
        {...attributes}
        {...listeners}
        aria-label="Drag to reorder"
      >
        ⠿
      </span>
      <span className="scan-queue-card-name">{cleanName(entry.name)}</span>
      {isCancelling && <span className="scan-queue-stopping">Stopping…</span>}
      {!disabled && (
        <button
          className="scan-queue-remove"
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onRemove(entry.uid);
          }}
          aria-label="Remove from queue"
        >
          ×
        </button>
      )}
    </div>
  );
}

function ScanCatalogueItem({ scan, onFocus, disabled }) {
  const { attributes, listeners, setNodeRef, isDragging } = useDraggable({
    id: scan.name,
    data: { source: "catalogue" },
    disabled,
  });

  return (
    <button
      ref={setNodeRef}
      className={`scan-item${isDragging ? " dragging" : ""}`}
      type="button"
      disabled={disabled}
      onClick={() => onFocus(scan)}
      {...attributes}
      {...listeners}
    >
      {cleanName(scan.name)}
    </button>
  );
}

function QueueDropZone({ children }) {
  const { setNodeRef, isOver } = useDroppable({ id: "queue-droppable" });
  return (
    <div ref={setNodeRef} className={`scan-queue-col${isOver ? " over" : ""}`}>
      {children}
    </div>
  );
}

export default function ScanPage({ activeTenantId, authStatus, setAuthStatus, refreshAuthStatus, refreshFiles }) {
  const [scans, setScans] = useState([]);
  const [scanQueue, setScanQueue] = useState([]);
  const [focusedScan, setFocusedScan] = useState(null);
  const [activeQueueIndex, setActiveQueueIndex] = useState(-1);
  const [completedIndices, setCompletedIndices] = useState(new Set());
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [isUtilityRun, setIsUtilityRun] = useState(false);
  const [output, setOutput] = useState([]);
  const [statusText, setStatusText] = useState("");
  const [completed, setCompleted] = useState(false);
  const [scanError, setScanError] = useState("");
  const [authOpen, setAuthOpen] = useState(!authStatus?.isAuthenticated);
  const [activeDrag, setActiveDrag] = useState(null);
  const [verbose, setVerbose] = useState(false);
  // One entry per SCAN_TOGGLES item, keyed by stateKey — e.g. { frontDoorProbePayload: false }.
  const [scanToggleValues, setScanToggleValues] = useState({});
  const esRef = useRef(null);
  const outputEndRef = useRef(null);

  useEffect(() => {
    fetch("/api/scans")
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => setScans(data))
      .catch(() => {});
    fetch("/api/settings/verbosity")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => { if (data) setVerbose(data.verbosity === "debug"); })
      .catch(() => {});
    SCAN_TOGGLES.forEach((toggle) => {
      fetch(toggle.settingsPath)
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (data) setScanToggleValues((prev) => ({ ...prev, [toggle.stateKey]: !!data.enabled }));
        })
        .catch(() => {});
    });
  }, []);

  useEffect(() => {
    setAuthOpen(!authStatus.isAuthenticated);
  }, [authStatus.isAuthenticated]);

  const runningRef = useRef(false);
  useEffect(() => {
    runningRef.current = running;
  }, [running]);

  useEffect(() => {
    // A scan keeps running server-side even after we tear down this client's view of it —
    // cancel it so switching tenants mid-scan actually stops it instead of just hiding it.
    if (runningRef.current) {
      fetch("/api/scans/cancel", { method: "POST" }).catch(() => {});
    }
    closeEventSource();
    setRunning(false);
    setCancelling(false);
    setIsUtilityRun(false);
    setOutput([]);
    setStatusText("");
    setCompleted(false);
    setScanError("");
    setScanQueue([]);
    setFocusedScan(null);
    setActiveQueueIndex(-1);
    setCompletedIndices(new Set());
  }, [activeTenantId]);

  useEffect(() => {
    outputEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [output]);

  useEffect(() => () => closeEventSource(), []);

  function closeEventSource() {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }

  const scanGroups = useMemo(() => {
    const groups = [
      { key: "scan", label: "Scans", items: scans.filter((s) => s.type === "scan") },
      { key: "util", label: "Exports & Utilities", items: scans.filter((s) => s.type !== "scan") },
    ];
    return groups.filter((g) => g.items.length > 0);
  }, [scans]);

  function addToQueue(scan, atIndex = -1) {
    const entry = { ...scan, uid: crypto.randomUUID() };
    setScanQueue((prev) => {
      if (atIndex < 0 || atIndex >= prev.length) return [...prev, entry];
      const updated = [...prev];
      updated.splice(atIndex, 0, entry);
      return updated;
    });
  }

  function removeFromQueue(uid) {
    setScanQueue((prev) => prev.filter((e) => e.uid !== uid));
  }

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } })
  );

  function handleDragStart({ active }) {
    if (active.data.current?.source === "catalogue") {
      setActiveDrag({ source: "catalogue", item: scans.find((s) => s.name === active.id) });
    } else {
      setActiveDrag({ source: "queue", item: scanQueue.find((e) => e.uid === active.id) });
    }
  }

  function handleDragEnd({ active, over }) {
    setActiveDrag(null);
    const isCatalogue = active.data.current?.source === "catalogue";

    if (isCatalogue) {
      if (!over) return;
      const scan = scans.find((s) => s.name === active.id);
      if (!scan) return;
      if (over.id === "queue-droppable") {
        addToQueue(scan);
      } else {
        const overIndex = scanQueue.findIndex((e) => e.uid === over.id);
        addToQueue(scan, overIndex >= 0 ? overIndex : -1);
      }
    } else {
      if (!over) return;
      const oldIndex = scanQueue.findIndex((e) => e.uid === active.id);
      const newIndex = scanQueue.findIndex((e) => e.uid === over.id);
      if (oldIndex !== -1 && newIndex !== -1 && oldIndex !== newIndex) {
        setScanQueue((prev) => arrayMove(prev, oldIndex, newIndex));
      }
    }
  }

  async function startRun({ utility = false, endpoint, body }) {
    if (running || !authStatus.isAuthenticated) return;
    setScanError("");
    setCompleted(false);
    setCancelling(false);
    setIsUtilityRun(utility);
    setOutput([]);
    setStatusText("");
    setActiveQueueIndex(-1);
    setCompletedIndices(new Set());
    closeEventSource();

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setScanError(extractError(data, "Failed to start scan."));
        return;
      }
    } catch {
      setScanError("Could not reach server.");
      return;
    }

    setRunning(true);
    const es = new EventSource("/api/scans/status");
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        const { type, text } = event;
        if (type === "line") {
          setOutput((prev) => [...prev, text]);
        } else if (type === "status") {
          setStatusText(text || "");
        } else if (type === "queue_start") {
          const meta = JSON.parse(text);
          setActiveQueueIndex(meta.index);
          setStatusText(`Running ${meta.index + 1}/${meta.total}: ${cleanName(meta.name)}`);
        } else if (type === "queue_done") {
          const meta = JSON.parse(text);
          setCompletedIndices((prev) => new Set([...prev, meta.index]));
        } else if (type === "scan_error") {
          // Non-fatal: one scan in the queue failed, the rest continue.
          setOutput((prev) => [...prev, text]);
          setScanError((prev) => prev ? prev + "\n" + text : text);
        } else if (type === "error") {
          setScanError(text || "Scan failed.");
          setOutput((prev) => [...prev, text]);
          setRunning(false);
          setCancelling(false);
          setIsUtilityRun(false);
          setCompleted(true);
          setStatusText("");
          setActiveQueueIndex(-1);
          es.close();
          esRef.current = null;
          refreshFiles?.();
        } else if (type === "complete") {
          setRunning(false);
          setCancelling(false);
          setIsUtilityRun(false);
          setCompleted(true);
          setStatusText("");
          setActiveQueueIndex(-1);
          es.close();
          esRef.current = null;
          refreshFiles?.();
        } else if (type === "cancelled") {
          setRunning(false);
          setCancelling(false);
          setIsUtilityRun(false);
          setCompleted(false);
          setScanError("Scan cancelled.");
          setStatusText("");
          setActiveQueueIndex(-1);
          es.close();
          esRef.current = null;
          refreshFiles?.();
        }
      } catch {
        // malformed event — ignore
      }
    };

    es.onerror = () => {
      if (esRef.current) {
        setRunning(false);
        setCancelling(false);
        setIsUtilityRun(false);
        setActiveQueueIndex(-1);
        setCompletedIndices(new Set());
        setScanError("Connection to scan stream lost.");
        es.close();
        esRef.current = null;
      }
    };
  }

  function handleRun() {
    if (!scanQueue.length) return;
    return startRun({
      endpoint: "/api/scans/run",
      body: { scanQueue: scanQueue.map((e) => e.name), tenantId: activeTenantId },
    });
  }

  function handleRefreshGraphPermissions() {
    return startRun({
      utility: true,
      endpoint: "/api/scans/refresh-graph-permissions",
      body: { tenantId: activeTenantId },
    });
  }

  async function handleCancel() {
    setCancelling(true);
    try {
      await fetch("/api/scans/cancel", { method: "POST" });
    } catch {
      // the "cancelled" SSE event (or stream error) will still resolve UI state
    }
  }

  return (
    <DndContext
      sensors={sensors}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      onDragCancel={() => setActiveDrag(null)}
    >
      <div className="scan-page">
        {/* Left column — grouped scan catalogue */}
        <div className="scan-page-list">
          {scanGroups.map((group) => (
            <div key={group.key} className="scan-group">
              <p className="scan-group-label">{group.label}</p>
              {group.items.map((scan) => (
                <ScanCatalogueItem
                  key={scan.name}
                  scan={scan}
                  onFocus={setFocusedScan}
                  disabled={running}
                />
              ))}
            </div>
          ))}
        </div>

        {/* Right column */}
        <div className="scan-page-detail">
          {/* Controls column — auth + queue + run */}
          <div className="scan-page-controls-col">
            {/* Auth — pinned top */}
            <div className="scan-auth-collapse">
              <button
                type="button"
                className="scan-auth-collapse-header"
                onClick={() => setAuthOpen((o) => !o)}
              >
                <span className={`auth-dot${authStatus.isAuthenticated ? " authenticated" : ""}`} />
                <span className="scan-auth-collapse-label">
                  {authStatus.isAuthenticated
                    ? `Authenticated · ${authStatus.authMode}`
                    : "Not authenticated"}
                </span>
                <span className="scan-auth-collapse-arrow">{authOpen ? "▲" : "▼"}</span>
              </button>
              {authOpen && (
                <AuthSection
                  activeTenantId={activeTenantId}
                  authStatus={authStatus}
                  setAuthStatus={setAuthStatus}
                  refreshAuthStatus={refreshAuthStatus}
                />
              )}
            </div>

            <button
              className={`auth-btn auth-btn-secondary scan-utility-btn${cancelling && isUtilityRun ? " scan-cancel-btn" : ""}`}
              type="button"
              onClick={isUtilityRun && running ? handleCancel : handleRefreshGraphPermissions}
              disabled={(running && !isUtilityRun) || cancelling || (!running && !authStatus.isAuthenticated)}
              title={
                isUtilityRun && running
                  ? "Cancel the Graph permissions refresh"
                  : "Refreshes the local Graph permission-name cache used to resolve permission names in scan results."
              }
            >
              {isUtilityRun && running
                ? (cancelling ? "Stopping…" : "Cancel Refresh")
                : "Refresh Graph Permissions"}
            </button>

            <div className="scan-page-divider" />

            {/* Queue — scrollable middle */}
            <SortableContext
              items={scanQueue.map((e) => e.uid)}
              strategy={verticalListSortingStrategy}
            >
              <QueueDropZone>
                {scanQueue.length === 0 ? (
                  <p className="scan-queue-hint">Drag scans here to queue them.</p>
                ) : (
                  scanQueue.map((entry, i) => (
                    <Fragment key={entry.uid}>
                      <ScanQueueCard
                        entry={entry}
                        isActive={!isUtilityRun && activeQueueIndex === i}
                        isCompleted={completedIndices.has(i)}
                        isCancelling={cancelling && !isUtilityRun && activeQueueIndex === i}
                        onRemove={removeFromQueue}
                        onFocus={setFocusedScan}
                        disabled={running}
                      />
                      {i < scanQueue.length - 1 && (
                        <div
                          className={`scan-queue-connector${!isUtilityRun && activeQueueIndex === i ? " active" : ""}`}
                          aria-hidden="true"
                        >↓</div>
                      )}
                    </Fragment>
                  ))
                )}
              </QueueDropZone>
            </SortableContext>

            {/* Run area — pinned bottom */}
            <div className="scan-queue-run-area">
              {statusText && <p className="scan-status-text">{statusText}</p>}
              {scanError && <p className="auth-error">{scanError}</p>}
              {completed && !scanError && (
                <p className="scan-complete-note">Queue complete — files updated.</p>
              )}
              {!authStatus.isAuthenticated && (
                <p className="scan-section-note">Authenticate above to run scans.</p>
              )}
              <label className="scan-verbose-toggle">
                <input
                  type="checkbox"
                  checked={verbose}
                  disabled={running}
                  onChange={(e) => {
                    const next = e.target.checked;
                    setVerbose(next);
                    fetch("/api/settings/verbosity", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ verbosity: next ? "debug" : "normal" }),
                    }).catch(() => {});
                  }}
                />
                Verbose output
              </label>
              {SCAN_TOGGLES.filter((toggle) =>
                scanQueue.some((entry) => entry.name === toggle.scanName)
              ).map((toggle) => (
                <label key={toggle.stateKey} className="scan-verbose-toggle" title={toggle.tooltip}>
                  <input
                    type="checkbox"
                    checked={!!scanToggleValues[toggle.stateKey]}
                    disabled={running}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setScanToggleValues((prev) => ({ ...prev, [toggle.stateKey]: next }));
                      fetch(toggle.settingsPath, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ enabled: next }),
                      }).catch(() => {});
                    }}
                  />
                  {toggle.label}
                </label>
              ))}
              <div className="scan-run-actions">
                <button
                  className="auth-btn scan-run-btn"
                  type="button"
                  onClick={handleRun}
                  disabled={running || !scanQueue.length || !authStatus.isAuthenticated}
                >
                  {running
                    ? "Running…"
                    : `Run${scanQueue.length > 0 ? ` (${scanQueue.length})` : ""}`}
                </button>
                {running && !isUtilityRun && (
                  <button
                    className="auth-btn auth-btn-secondary scan-cancel-btn"
                    type="button"
                    onClick={handleCancel}
                    disabled={cancelling}
                  >
                    {cancelling ? "Stopping…" : "Cancel Scan"}
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Output column — description or terminal */}
          <div className="scan-page-output-col">
            {!running && output.length === 0 && focusedScan?.description ? (
              <pre className="scan-description">{focusedScan.description}</pre>
            ) : (
              <div className="scan-page-output">
                {output.map((line, i) => (
                  <div key={i} className="scan-output-line">
                    {line}
                  </div>
                ))}
                <div ref={outputEndRef} />
              </div>
            )}
          </div>
        </div>
      </div>
      <DragOverlay dropAnimation={null}>
        {activeDrag?.item ? (
          <div className="scan-queue-card drag-overlay">
            <span className="scan-queue-drag-handle">⠿</span>
            <span className="scan-queue-card-name">{cleanName(activeDrag.item.name)}</span>
          </div>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}
