import { useEffect, useState } from "react";
import { buildTenantFileGroups, formatScanType, formatDateKey } from "../lib/files.js";
import Frame from "./Frame.jsx";

export default function FilesPane({ files, activeTenantId, activeFile, loadFile, deleteFile, openScanPane }) {
  const tenantFiles = (files || []).filter((f) => f.tenantId === activeTenantId);
  const dateGroups = buildTenantFileGroups(files, activeTenantId);

  const [expanded, setExpanded] = useState(() => new Set());

  // Auto-expand the date group containing the active file
  useEffect(() => {
    if (!activeFile || !dateGroups.length) return;
    const group = dateGroups.find((g) => g.files.some((f) => f.name === activeFile));
    if (group) {
      setExpanded((prev) => {
        if (prev.has(group.dateKey)) return prev;
        const next = new Set(prev);
        next.add(group.dateKey);
        return next;
      });
    }
  }, [activeFile]);

  // Auto-expand the latest date group when files first load
  useEffect(() => {
    if (dateGroups.length > 0) {
      setExpanded((prev) => {
        if (prev.size > 0) return prev;
        return new Set([dateGroups[0].dateKey]);
      });
    }
  }, [dateGroups.length]);

  function toggle(dateKey) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(dateKey)) next.delete(dateKey);
      else next.add(dateKey);
      return next;
    });
  }

  return (
    <Frame
      title="Scans"
      count={tenantFiles.length}
      className="panel sidebar-files"
      bodyClassName="file-list"
      scroll
    >
      {dateGroups.length === 0 && (
        <button className="no-files-cta" type="button" onClick={openScanPane}>
          No scans yet — launch one
        </button>
      )}
      {dateGroups.map((group) => {
        const isOpen = expanded.has(group.dateKey);
        const hasActive = group.files.some((f) => f.name === activeFile);

        return (
          <div key={group.dateKey} className={`scan-type-group${hasActive ? " has-active" : ""}`}>
            <button
              type="button"
              className={`scan-type-header${isOpen ? " open" : ""}`}
              onClick={() => toggle(group.dateKey)}
            >
              <span className="scan-type-chevron">{isOpen ? "▾" : "▸"}</span>
              <span className="scan-type-name">{formatDateKey(group.dateKey)}</span>
              <span className="scan-date-count">{group.files.length}</span>
            </button>

            {isOpen && (
              <div className="scan-type-files">
                {group.files.map((file) => (
                  <div
                    key={file.name}
                    className={`scan-type-file-item${file.name === activeFile ? " active" : ""}`}
                  >
                    <button
                      type="button"
                      className="file-item-load"
                      onClick={() => loadFile(file.name)}
                    >
                      <span className="file-run-date">
                        {file.isAggregate ? "All Scans" : formatScanType(file.scanType)}
                      </span>
                      <div className="finding-counts">
                        {(file.findingCounts?.high || 0) > 0 && (
                          <span className="finding-count high">{file.findingCounts.high}</span>
                        )}
                        {(file.findingCounts?.medium || 0) > 0 && (
                          <span className="finding-count medium">{file.findingCounts.medium}</span>
                        )}
                        {(file.findingCounts?.low || 0) > 0 && (
                          <span className="finding-count low">{file.findingCounts.low}</span>
                        )}
                      </div>
                    </button>
                    <button
                      type="button"
                      className="file-item-delete"
                      onClick={(e) => { e.stopPropagation(); deleteFile(file.name); }}
                      aria-label="Delete file"
                      title="Delete"
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </Frame>
  );
}
