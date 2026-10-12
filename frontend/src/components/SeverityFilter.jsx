import Frame from "./Frame.jsx";

export default function SeverityFilter({ severityOrder, severity, counts, findingsCount, setSeverity }) {
  return (
    <Frame title="Severities" className="panel stats" bodyClassName="stats">
      {severityOrder.map((level) => (
        <button
          key={level}
          className={`severity-chip ${level}${severity === level ? " selected" : ""}`}
          onClick={() => setSeverity(level)}
          type="button"
        >
          <span>{level === "medium" ? "Med" : level}</span>
          <strong>{counts[level] || 0}</strong>
        </button>
      ))}
      <button
        className={`severity-chip neutral${severity === "all" ? " selected" : ""}`}
        onClick={() => setSeverity("all")}
        type="button"
      >
        <span>all</span>
        <strong>{findingsCount}</strong>
      </button>
    </Frame>
  );
}
