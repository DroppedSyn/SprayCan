export default function Toolbar({
  activeFile,
  activeFileMeta,
  networkModel,
  query,
  theme,
  formatFileLabel,
  formatDateKey,
  getTenantDisplayName,
  setQuery,
  toggleTheme,
}) {
  return (
    <header className="toolbar">
      <div className="toolbar-copy">
        <p className="eyebrow">Active File</p>
        <h2 title={activeFile || "No file selected"}>
          {activeFile ? formatFileLabel(activeFile) : "No file selected"}
        </h2>
        {activeFile ? (
          <div className="toolbar-tags">
            <span className="toolbar-tag">{formatDateKey(activeFileMeta.dateKey)}</span>
            <span className="toolbar-tag">{getTenantDisplayName(activeFileMeta.tenantId)}</span>
            <span className="toolbar-tag">{activeFileMeta.isAggregate ? "Aggregate" : "Single scan"}</span>
          </div>
        ) : null}
        {activeFile ? (
          <p className="toolbar-meta" title={activeFile}>
            {activeFile}
          </p>
        ) : null}
      </div>
      <label className="search-field">
        <span className="search-label">{networkModel ? "Search Topology" : "Search Findings"}</span>
        <input
          className="search"
          type="search"
          placeholder={networkModel ? "Filter topology items, names, ids, and metadata" : "Filter findings, objects, evidence, and scan names"}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      <button className="theme-toggle" type="button" onClick={toggleTheme}>
        {theme === "dark" ? "Light" : "Dark"}
      </button>
    </header>
  );
}
