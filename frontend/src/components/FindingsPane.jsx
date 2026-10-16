import Frame from "./Frame.jsx";

export default function FindingsPane({
  activeFile,
  networkModel,
  status,
  filteredFindings,
  filteredNetworkInventory,
  groupedNetworkInventory,
  expandedTopologyGroups,
  selectedNetworkItem,
  setSelectedNetworkKey,
  toggleTopologyGroup,
  summarizeFinding,
  expandedFindings,
  selectedFinding,
  setSelectedId,
  toggleFinding,
  shortId,
  formatScanName,
}) {
  return (
    <Frame
      title={networkModel ? "Topology" : "Findings"}
      count={networkModel ? filteredNetworkInventory.length : filteredFindings.length}
      className="finding-list"
      bodyClassName="finding-list-body"
      scroll
    >
      {status === "loading" ? <div className="empty-state">Loading findings…</div> : null}
      {status === "ready" && !networkModel && !activeFile ? (
        <div className="empty-state">No scan open. Pick a tenant, then a scan from the sidebar.</div>
      ) : null}
      {status === "ready" && !networkModel && activeFile && filteredFindings.length === 0 ? (
        <div className="empty-state">No findings match the current filters.</div>
      ) : null}
      {status === "ready" && networkModel && filteredNetworkInventory.length === 0 ? (
        <div className="empty-state">No topology items match the current filters.</div>
      ) : null}
      {networkModel
        ? groupedNetworkInventory.map((group) => (
            <div key={group.kind} className="topology-group">
              <button
                className="topology-group-header"
                type="button"
                onClick={() => toggleTopologyGroup(group.kind)}
              >
                <div className="card-row">
                  <span className={`badge network-${group.kind}`}>{group.label}</span>
                </div>
                <div className="topology-group-meta">
                  <span className="frame-count">{group.items.length}</span>
                  <span className="collapse-indicator">{expandedTopologyGroups[group.kind] ? "−" : "+"}</span>
                </div>
              </button>
              {expandedTopologyGroups[group.kind] ? (
                <div className="topology-group-list">
                  {group.items.map((item) => (
                    <button
                      key={item.key}
                      className={`finding-card network-card${selectedNetworkItem?.key === item.key ? " active" : ""}`}
                      onClick={() => setSelectedNetworkKey(item.key)}
                      type="button"
                    >
                      <div className="finding-summary">
                        <div className="card-row">
                          <span className={`badge network-${item.kind}`}>{item.kind}</span>
                          <h3>{item.title}</h3>
                        </div>
                        <p className="card-submeta">{item.meta}</p>
                      </div>
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          ))
        : filteredFindings.map((finding) => {
            const summary = summarizeFinding(finding);
            const isExpanded = Boolean(expandedFindings[finding.id]);
            return (
              <div
                key={finding.id}
                className={`finding-card${selectedFinding?.id === finding.id ? " active" : ""}${isExpanded ? " expanded" : ""}`}
              >
                <button
                  className="finding-summary"
                  onClick={() => {
                    setSelectedId(finding.id);
                    toggleFinding(finding.id);
                  }}
                  type="button"
                  aria-expanded={isExpanded}
                >
                  <div className="card-row">
                    <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                    <h3>{summary.eyebrow}</h3>
                  </div>
                  <div className="card-row compact">
                    <span className="mono" title={formatScanName(finding)}>{formatScanName(finding)}</span>
                    <span className="collapse-indicator">{isExpanded ? "−" : "+"}</span>
                  </div>
                </button>
                {isExpanded ? (
                  <div className="finding-body">
                    <p className="card-meta" title={formatScanName(finding)}>{formatScanName(finding)}</p>
                    {summary.fields ? (
                      summary.fields.map((field) => (
                        <div className="finding-field" key={field.label}>
                          <span className="finding-field-label">{field.label}</span>
                          <p className="finding-field-value">{field.value}</p>
                        </div>
                      ))
                    ) : (
                      <>
                        <p className="card-headline">{summary.headline}</p>
                        {summary.meta ? <p className="card-submeta">{summary.meta}</p> : null}
                      </>
                    )}
                  </div>
                ) : null}
              </div>
            );
          })}
    </Frame>
  );
}
