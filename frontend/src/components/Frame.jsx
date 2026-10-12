export default function Frame({
  title,
  count,
  headerRight,
  className = "",
  bodyClassName = "",
  scroll = false,
  children,
}) {
  return (
    <section className={`frame ${className}`.trim()}>
      {title || count !== undefined || headerRight ? (
        <div className="frame-header">
          {title ? <h2>{title}</h2> : <div />}
          {headerRight || (count !== undefined ? <span className="frame-count">{count}</span> : null)}
        </div>
      ) : null}
      <div className={`frame-body ${scroll ? "frame-scroll" : ""} ${bodyClassName}`.trim()}>
        {children}
      </div>
    </section>
  );
}
