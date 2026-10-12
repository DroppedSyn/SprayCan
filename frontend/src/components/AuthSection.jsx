import { useEffect, useRef, useState } from "react";

function extractError(data, fallback) {
  const d = data?.detail;
  if (!d) return fallback;
  if (typeof d === "string") return d;
  if (d.detail) return d.detail;
  if (d.error) return d.error;
  return JSON.stringify(d);
}

const TOKEN_TYPE_LABELS = {
  arm_access_token: "ARM access token",
  graph_access_token: "Graph access token",
  unknown_jwt: "Unknown JWT (accepted)",
  likely_refresh_token: "Refresh token exchanged",
};

const TABS = [
  { id: "browser", label: "Browser" },
  { id: "devicecode", label: "Device Code" },
  { id: "sp", label: "SP" },
  { id: "token", label: "Token" },
];

export default function AuthSection({ activeTenantId, authStatus, setAuthStatus, refreshAuthStatus }) {
  const [activeTab, setActiveTab] = useState("browser");
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState("");
  const [spForm, setSpForm] = useState({ clientId: "", clientSecret: "" });
  const [tokenForm, setTokenForm] = useState({ token: "" });
  const [scopeHint, setScopeHint] = useState("graph");
  const [deviceCodeInfo, setDeviceCodeInfo] = useState(null);
  const deviceCodePollRef = useRef(null);
  const activeTenantIdRef = useRef(activeTenantId);

  useEffect(() => {
    activeTenantIdRef.current = activeTenantId;
  }, [activeTenantId]);

  useEffect(() => {
    return () => clearInterval(deviceCodePollRef.current);
  }, []);

  // A device-code poll started for one tenant must not resolve against a different tenant —
  // stop it outright whenever the active tenant changes underneath it.
  useEffect(() => {
    stopDeviceCodePolling();
    setDeviceCodeInfo(null);
  }, [activeTenantId]);

  function stopDeviceCodePolling() {
    clearInterval(deviceCodePollRef.current);
    deviceCodePollRef.current = null;
  }

  async function handleDeviceCodeStart() {
    setLoading(true);
    setAuthError("");
    setDeviceCodeInfo(null);
    const tenantAtStart = activeTenantId;
    try {
      const res = await fetch("/api/auth/device-code/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: tenantAtStart }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(extractError(data, "Could not start device code sign-in."));
        setLoading(false);
        return;
      }
      setDeviceCodeInfo(data);
      deviceCodePollRef.current = setInterval(async () => {
        if (activeTenantIdRef.current !== tenantAtStart) {
          stopDeviceCodePolling();
          return;
        }
        try {
          const pollRes = await fetch(`/api/auth/device-code/status?tenantId=${encodeURIComponent(tenantAtStart)}`);
          const pollData = await pollRes.json();
          // Re-check after the await — the tenant may have changed while this request was in flight.
          if (activeTenantIdRef.current !== tenantAtStart) {
            stopDeviceCodePolling();
            return;
          }
          if (pollData.status === "success") {
            stopDeviceCodePolling();
            setDeviceCodeInfo(null);
            setLoading(false);
            setAuthStatus(pollData.authState);
          } else if (pollData.status === "error") {
            stopDeviceCodePolling();
            setDeviceCodeInfo(null);
            setLoading(false);
            setAuthError(pollData.error || "Device code sign-in failed.");
          }
        } catch {
          // transient network error — keep polling
        }
      }, 3000);
    } catch {
      setAuthError("Could not reach server.");
      setLoading(false);
    }
  }

  async function handleSPConnect() {
    setLoading(true);
    setAuthError("");
    try {
      const res = await fetch("/api/auth/sp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenantId: activeTenantId,
          clientId: spForm.clientId.trim(),
          clientSecret: spForm.clientSecret.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(extractError(data, "SP authentication failed."));
      } else {
        setAuthStatus(data);
        setSpForm({ clientId: "", clientSecret: "" });
      }
    } catch {
      setAuthError("Could not reach server.");
    } finally {
      setLoading(false);
    }
  }

  async function handleBrowserSignIn() {
    setLoading(true);
    setAuthError("");
    try {
      const res = await fetch("/api/auth/browser", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: activeTenantId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(extractError(data, "Authentication failed."));
      } else {
        setAuthStatus(data);
      }
    } catch {
      setAuthError("Could not reach server.");
    } finally {
      setLoading(false);
    }
  }

  async function handleTokenSubmit() {
    setLoading(true);
    setAuthError("");
    try {
      const res = await fetch("/api/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenantId: activeTenantId,
          token: tokenForm.token.trim(),
          scopeHint,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(extractError(data, "Token submission failed."));
      } else {
        setAuthStatus(data);
        setTokenForm({ token: "" });
      }
    } catch {
      setAuthError("Could not reach server.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSignOut() {
    setLoading(true);
    setAuthError("");
    stopDeviceCodePolling();
    setDeviceCodeInfo(null);
    try {
      const res = await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: activeTenantId }),
      });
      if (res.ok) setAuthStatus(await res.json());
    } catch {
      setAuthError("Sign out failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-section">
      <div className="auth-status-bar">
        <span className={`auth-dot${authStatus.isAuthenticated ? " authenticated" : ""}`} />
        <span className="auth-status-label">
          {authStatus.isAuthenticated
            ? `Authenticated · ${authStatus.authMode}`
            : "Not authenticated"}
        </span>
      </div>

      {authError && <p className="auth-error">{authError}</p>}

      <div className="auth-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={`auth-tab${activeTab === tab.id ? " active" : ""}`}
            onClick={() => { setActiveTab(tab.id); setAuthError(""); }}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tenant display — read-only, driven by active tenant in selector */}
      <div className="auth-field">
        <label>Tenant</label>
        <p className="auth-tenant-display">
          {activeTenantId || <span className="auth-hint">No tenant selected</span>}
        </p>
      </div>

      {activeTab === "browser" && (
        <div className="auth-form">
          {loading ? (
            <p className="auth-hint">Waiting for browser authentication…</p>
          ) : (
            <button
              className="auth-btn"
              type="button"
              onClick={handleBrowserSignIn}
              disabled={loading || !activeTenantId}
            >
              Sign In
            </button>
          )}
          <p className="auth-hint">Opens a browser window to authenticate via MSAL.</p>
        </div>
      )}

      {activeTab === "devicecode" && (
        <div className="auth-form">
          {deviceCodeInfo ? (
            <>
              <p className="auth-hint">
                Go to{" "}
                <a href={deviceCodeInfo.verificationUri} target="_blank" rel="noreferrer">
                  {deviceCodeInfo.verificationUri}
                </a>{" "}
                and enter this code:
              </p>
              <p className="auth-device-code">{deviceCodeInfo.userCode}</p>
              <p className="auth-hint">Waiting for you to complete sign-in…</p>
            </>
          ) : (
            <button
              className="auth-btn"
              type="button"
              onClick={handleDeviceCodeStart}
              disabled={loading || !activeTenantId}
            >
              {loading ? "Starting…" : "Start Device Code Sign-In"}
            </button>
          )}
          <p className="auth-hint">
            No local browser required — sign in from any browser, on any device.
          </p>
        </div>
      )}

      {activeTab === "sp" && (
        <div className="auth-form">
          <div className="auth-field">
            <label>Client ID</label>
            <input
              className="auth-input"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={spForm.clientId}
              onChange={(e) => setSpForm({ ...spForm, clientId: e.target.value })}
            />
          </div>
          <div className="auth-field">
            <label>Client Secret</label>
            <input
              className="auth-input"
              type="password"
              placeholder="••••••••"
              value={spForm.clientSecret}
              onChange={(e) => setSpForm({ ...spForm, clientSecret: e.target.value })}
            />
          </div>
          {authStatus.isAuthenticated && authStatus.authMode === "sp" && authStatus.spClientId && (
            <p className="auth-hint">Connected · client {authStatus.spClientId}</p>
          )}
          <button
            className="auth-btn"
            type="button"
            onClick={handleSPConnect}
            disabled={loading || !activeTenantId || !spForm.clientId.trim() || !spForm.clientSecret.trim()}
          >
            {loading ? "Connecting…" : "Connect"}
          </button>
          <p className="auth-hint">
            SP must have the required Graph application permissions pre-consented by an admin.
          </p>
        </div>
      )}

      {activeTab === "token" && (
        <div className="auth-form">
          <div className="auth-field">
            <label>Token</label>
            <textarea
              className="auth-input auth-textarea"
              placeholder="Paste access token or refresh token…"
              value={tokenForm.token}
              onChange={(e) => setTokenForm({ token: e.target.value })}
            />
          </div>
          <div className="auth-field">
            <label>Exchange scope <span className="auth-hint-inline">(refresh tokens only)</span></label>
            <div className="token-scope-toggle">
              <button
                type="button"
                className={`scope-btn${scopeHint === "graph" ? " active" : ""}`}
                onClick={() => setScopeHint("graph")}
              >
                Graph
              </button>
              <button
                type="button"
                className={`scope-btn${scopeHint === "arm" ? " active" : ""}`}
                onClick={() => setScopeHint("arm")}
              >
                ARM
              </button>
            </div>
          </div>
          {authStatus.isAuthenticated && authStatus.authMode === "token" && authStatus.tokenType && (
            <p className="auth-hint">{TOKEN_TYPE_LABELS[authStatus.tokenType] || authStatus.tokenType}</p>
          )}
          <button
            className="auth-btn"
            type="button"
            onClick={handleTokenSubmit}
            disabled={loading || !tokenForm.token.trim()}
          >
            {loading ? "Submitting…" : "Submit Token"}
          </button>
        </div>
      )}

      {authStatus.isAuthenticated && (
        <button
          className="auth-btn auth-btn-secondary"
          type="button"
          onClick={handleSignOut}
          disabled={loading}
        >
          Sign Out
        </button>
      )}
    </div>
  );
}
