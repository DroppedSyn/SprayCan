import { useEffect, useRef, useState } from "react";
import Frame from "./Frame.jsx";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(value) {
  return UUID_RE.test(value.trim());
}

export default function TenantSelector({
  tenants,
  activeTenantId,
  onSelectTenant,
  onRenameTenant,
  onRegisterTenant,
  onDeleteTenant,
}) {
  const [editingId, setEditingId] = useState("");
  const [editDraft, setEditDraft] = useState("");
  const [showRegister, setShowRegister] = useState(false);
  const [registerForm, setRegisterForm] = useState({ id: "", name: "" });
  const [registerError, setRegisterError] = useState("");
  const registerFormRef = useRef(null);

  useEffect(() => {
    if (showRegister) {
      registerFormRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [showRegister]);

  function startEdit(tenant) {
    setEditingId(tenant.id);
    setEditDraft(tenant.name || "");
  }

  function cancelEdit() {
    setEditingId("");
    setEditDraft("");
  }

  function handleDelete(tenant) {
    const label = tenant.name || tenant.id;
    if (!window.confirm(`Remove "${label}" from the tenant list?\n\nThis only deregisters it — existing findings files are not deleted.`)) {
      return;
    }
    onDeleteTenant(tenant.id);
  }

  async function commitEdit(tenantId) {
    await onRenameTenant(tenantId, editDraft.trim());
    cancelEdit();
  }

  async function handleRegister() {
    const id = registerForm.id.trim();
    if (!isValidUuid(id)) {
      setRegisterError("Enter a valid tenant UUID.");
      return;
    }
    setRegisterError("");
    await onRegisterTenant(id, registerForm.name.trim());
    setRegisterForm({ id: "", name: "" });
    setShowRegister(false);
  }

  return (
    <Frame
      title="Tenants"
      count={tenants.length}
      className={`panel sidebar-tenants${showRegister ? " registering" : ""}`}
      bodyClassName="tenant-selector-body"
    >
      {showRegister ? (
        <div className="tenant-register-form" ref={registerFormRef}>
          <div className="auth-field">
            <label>Tenant ID</label>
            <input
              className="auth-input"
              type="text"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={registerForm.id}
              onChange={(e) => setRegisterForm({ ...registerForm, id: e.target.value })}
              autoFocus
            />
          </div>
          <div className="auth-field">
            <label>Name <span className="auth-hint-inline">(optional)</span></label>
            <input
              className="auth-input"
              type="text"
              placeholder="e.g. Contoso Corp"
              value={registerForm.name}
              onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
              onKeyDown={(e) => { if (e.key === "Enter") handleRegister(); }}
            />
          </div>
          {registerError && <p className="auth-error">{registerError}</p>}
          <div className="tenant-register-actions">
            <button className="auth-btn" type="button" onClick={handleRegister}>Register</button>
            <button
              className="auth-btn auth-btn-secondary"
              type="button"
              onClick={() => { setShowRegister(false); setRegisterForm({ id: "", name: "" }); setRegisterError(""); }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button className="tenant-add-btn" type="button" onClick={() => setShowRegister(true)}>
          + Register tenant
        </button>
      )}

      {tenants.length === 0 && !showRegister && (
        <p className="tenant-empty-note">No tenants registered yet.</p>
      )}

      {tenants.map((tenant) => (
        <div
          key={tenant.id}
          className={`tenant-item${tenant.id === activeTenantId ? " active" : ""}`}
        >
          {editingId === tenant.id ? (
            <div className="tenant-edit-row">
              <input
                className="tenant-edit-input"
                type="text"
                placeholder="Display name"
                value={editDraft}
                onChange={(e) => setEditDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") commitEdit(tenant.id);
                  if (e.key === "Escape") cancelEdit();
                }}
                autoFocus
              />
              <button className="tenant-edit-save" type="button" onClick={() => commitEdit(tenant.id)}>✓</button>
              <button className="tenant-edit-cancel" type="button" onClick={cancelEdit}>✕</button>
            </div>
          ) : (
            <>
              <button
                className="tenant-item-main"
                type="button"
                onClick={() => onSelectTenant(tenant.id)}
              >
                <span className={`tenant-auth-dot${tenant.isAuthenticated ? " authenticated" : ""}`} />
                <span className="tenant-item-name">
                  {tenant.name || <span className="tenant-item-no-name">{tenant.id.slice(0, 8)}…</span>}
                </span>
                <span className="tenant-item-meta">
                  {tenant.name && <span className="tenant-item-id">{tenant.id.slice(0, 8)}…</span>}
                  {tenant.fileCount > 0 && (
                    <span className="tenant-item-count">{tenant.fileCount} {tenant.fileCount === 1 ? "file" : "files"}</span>
                  )}
                  {!tenant.isRegistered && <span className="tenant-item-badge">discovered</span>}
                </span>
              </button>
              <button
                className="tenant-item-edit"
                type="button"
                title="Rename tenant"
                onClick={(e) => { e.stopPropagation(); startEdit(tenant); }}
              >
                ✎
              </button>
              {tenant.isRegistered && (
                <button
                  className="tenant-item-delete"
                  type="button"
                  title="Remove tenant from list"
                  onClick={(e) => { e.stopPropagation(); handleDelete(tenant); }}
                >
                  🗑
                </button>
              )}
            </>
          )}
        </div>
      ))}
    </Frame>
  );
}
