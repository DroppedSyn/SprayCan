import AuthSection from "./AuthSection.jsx";
import Frame from "./Frame.jsx";
import ScanSection from "./ScanSection.jsx";

export default function ScanPane({ activeTenantId, authStatus, setAuthStatus, refreshAuthStatus, refreshFiles }) {
  return (
    <Frame title="Scan" className="panel sidebar-scan" bodyClassName="scan-pane-body" scroll>
      <AuthSection
        activeTenantId={activeTenantId}
        authStatus={authStatus}
        setAuthStatus={setAuthStatus}
        refreshAuthStatus={refreshAuthStatus}
      />
      <div className="scan-pane-divider" />
      <ScanSection
        authStatus={authStatus}
        activeTenantId={activeTenantId}
        refreshFiles={refreshFiles}
      />
    </Frame>
  );
}
