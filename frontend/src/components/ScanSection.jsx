import { useEffect, useRef, useState } from "react";

export default function ScanSection({ authStatus, activeTenantId, refreshFiles }) {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState([]);
  const [statusText, setStatusText] = useState("");
  const [completed, setCompleted] = useState(false);
  const [scanError, setScanError] = useState("");
  const esRef = useRef(null);
  const outputEndRef = useRef(null);

  useEffect(() => {
    if (!authStatus.isAuthenticated) {
      setScans([]);
      setSelectedScan("");
      return;
    }
    fetch("/api/scans")
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        setScans(data);
        if (data.length > 0) setSelectedScan(data[0].name);
      })
      .catch(() => {});
  }, [authStatus.isAuthenticated]);

  useEffect(() => {
    outputEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [output]);

  useEffect(() => {
    if (!authStatus.isAuthenticated) {
      closeEventSource();
      setRunning(false);
    }
  }, [authStatus.isAuthenticated]);

  useEffect(() => () => closeEventSource(), []);

  function closeEventSource() {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }

  async function handleRun() {
    if (!selectedScan || running) return;
    setScanError("");
    setCompleted(false);
    setOutput([]);
    setStatusText("");
    closeEventSource();

    try {
      const res = await fetch("/api/scans/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanName: selectedScan, tenantId: activeTenantId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setScanError(data?.detail?.error || data?.detail || "Failed to start scan.");
        return;
      }
    } catch {
      setScanError("Could not reach server.");
      return;
    }

    // POST returned ok — open the event stream
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
        } else if (type === "error") {
          setScanError(text || "Scan failed.");
          setOutput((prev) => [...prev, text]);
          setRunning(false);
          setCompleted(true);
          setStatusText("");
          es.close();
          esRef.current = null;
          refreshFiles?.();
        } else if (type === "complete") {
          setRunning(false);
          setCompleted(true);
          setStatusText("");
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
        setScanError("Connection to scan stream lost.");
        es.close();
        esRef.current = null;
      }
    };
  }

  if (!authStatus.isAuthenticated) {
    return (
      <div className="scan-section">
        <div className="scan-section-header">
          <p className="scan-section-label">Scans</p>
        </div>
        <p className="scan-section-note">Authenticate above to enable scan launch.</p>
      </div>
    );
  }

  return (
    <div className="scan-section">
      <div className="scan-section-header">
        <p className="scan-section-label">Scans</p>
        {running && <span className="scan-running-indicator">Running…</span>}
      </div>

      {scans.length === 0 ? (
        <p className="scan-section-note">No scans available.</p>
      ) : (
        <div className="scan-controls">
          <select
            className="scan-select"
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
            disabled={running}
          >
            {scans.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
              </option>
            ))}
          </select>
          <button
            className="auth-btn scan-run-btn"
            type="button"
            onClick={handleRun}
            disabled={running || !selectedScan}
          >
            {running ? "Running…" : "Run"}
          </button>
        </div>
      )}

      {statusText && <p className="scan-status-text">{statusText}</p>}

      {output.length > 0 && (
        <div className="scan-output">
          {output.map((line, i) => (
            <div key={i} className="scan-output-line">
              {line}
            </div>
          ))}
          <div ref={outputEndRef} />
        </div>
      )}

      {scanError && <p className="auth-error">{scanError}</p>}

      {completed && !scanError && (
        <p className="scan-complete-note">Scan complete — files updated.</p>
      )}
    </div>
  );
}
