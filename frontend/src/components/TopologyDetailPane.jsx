import { useEffect, useRef, useState } from "react";
import TopologyGraph from "./TopologyGraph.jsx";
import ExportCsvButton from "./ExportCsvButton.jsx";
import {
  formatFactValue,
  formatRuleDestination,
  formatRuleDestinationPorts,
  formatRuleSource,
  formatRuleSourcePorts,
} from "../lib/topology.js";

const NSG_RULE_COLUMNS = [
  { label: "Name", key: "name" },
  { label: "Priority", key: "priority" },
  { label: "Direction", key: "direction" },
  { label: "Access", key: "access" },
  { label: "Protocol", key: "protocol" },
  { label: "Source", format: formatRuleSource },
  { label: "Source Port", format: formatRuleSourcePorts },
  { label: "Destination", format: formatRuleDestination },
  { label: "Destination Port", format: formatRuleDestinationPorts },
];

function nsgRuleCell(rule, label) {
  const column = NSG_RULE_COLUMNS.find((col) => col.label === label);
  return column.format ? column.format(rule) : rule[column.key];
}

const ROUTE_COLUMNS = [
  { label: "Name", key: "name" },
  { label: "Prefix", key: "address_prefix" },
  { label: "Next Hop", key: "next_hop_type" },
  { label: "Next Hop IP", key: "next_hop_ip_address" },
];

export default function TopologyDetailPane({
  selectedNetworkItem,
  networkSecurityGroups,
  networkRouteTables,
  networkFocusSummary,
  networkView,
  setNetworkView,
  networkFocus,
  toggleNetworkFocus,
  scopedNetworkGraph,
  activeGraphNodeId,
  theme,
  filteredNetworkInventory,
  findNetworkInventoryKey,
  setSelectedNetworkKey,
  pluralize,
}) {
  const [activeTab, setActiveTab] = useState("details");
  const [expandedNsgs, setExpandedNsgs] = useState({});
  const [expandedRouteTables, setExpandedRouteTables] = useState({});
  const [nsgSearchMode, setNsgSearchMode] = useState("name");
  const [nsgQuery, setNsgQuery] = useState("");
  const [graphFullscreen, setGraphFullscreen] = useState(false);
  const graphRef = useRef(null);

  useEffect(() => {
    setActiveTab("details");
  }, [selectedNetworkItem?.key]);

  useEffect(() => {
    if (!graphFullscreen) return undefined;
    function onKey(e) {
      if (e.key === "Escape") setGraphFullscreen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [graphFullscreen]);

  if (!selectedNetworkItem) {
    return <div className="empty-state">Select a topology item to inspect it.</div>;
  }

  const normalizedNsgQuery = nsgQuery.trim().toLowerCase();
  const filteredNetworkSecurityGroups = networkSecurityGroups.filter((group) => {
    if (!normalizedNsgQuery) {
      return true;
    }

    if (nsgSearchMode === "name") {
      return (group.name || "").toLowerCase().includes(normalizedNsgQuery);
    }

    if (nsgSearchMode === "vnet") {
      return group.attached_subnets.some((subnet) =>
        (subnet.virtual_network_name || "").toLowerCase().includes(normalizedNsgQuery),
      );
    }

    if (nsgSearchMode === "nic") {
      return group.attached_nics.some((nic) =>
        `${nic.name || ""} ${nic.attached_resource_name || ""}`.toLowerCase().includes(normalizedNsgQuery),
      );
    }

    if (nsgSearchMode === "subnet") {
      return group.attached_subnets.some((subnet) =>
        (subnet.name || "").toLowerCase().includes(normalizedNsgQuery),
      );
    }

    return true;
  });

  function renderTabHeader(label, title, subtitle = "") {
    return (
      <div className={`topology-tab-header${activeTab === "details" ? " details" : ""}`}>
        <p className="mono long-id topology-tab-id">{label}</p>
        <h3>{title}</h3>
        {subtitle ? <p className="detail-copy">{subtitle}</p> : null}
      </div>
    );
  }

  function renderActiveHeader() {
    if (activeTab === "graph") {
      return renderTabHeader("topology:graph", "Graph");
    }

    if (activeTab === "nsgs") {
      return renderTabHeader("topology:nsgs", "Network Security Groups");
    }

    if (activeTab === "routes") {
      return renderTabHeader("topology:route_tables", "Route Tables");
    }

    return renderTabHeader(
      selectedNetworkItem.data.id || selectedNetworkItem.key,
      selectedNetworkItem.title,
      selectedNetworkItem.meta,
    );
  }

  return (
    <div className="topology-detail-pane">
      <div className="topology-pane-topbar">
        {renderActiveHeader()}
        <div className="network-panel-tabs">
          {[
            ["details", "Details"],
            ["graph", "Graph"],
            ["nsgs", "NSGs"],
            ["routes", "Route Tables"],
          ].map(([tab, label]) => (
            <button
              key={tab}
              type="button"
              className={`network-panel-tab ${tab} ${activeTab === tab ? "active" : ""}`}
              onClick={() => setActiveTab(tab)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === "graph" ? (
        <div className={`detail-block topology-graph-tab${graphFullscreen ? " graph-fullscreen" : ""}`}>
          <div className="network-graph-controls">
            <div className="network-view-bar vertical">
              {[
                ["shape", "Shape"],
                ["devices", "Devices"],
                ["topology", "Topology"],
              ].map(([view, label]) => (
                <button
                  key={view}
                  type="button"
                  className={`network-view-chip ${networkView === view ? "active" : ""}`}
                  onClick={() => setNetworkView(view)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="network-focus-bar vertical">
              {[
                ["publicIp", "Public IPs"],
                ["subnet", "Subnets"],
                ["device", "Devices"],
                ["peering", "Peerings"],
              ].map(([kind, label]) => (
                <button
                  key={kind}
                  type="button"
                  className={`network-focus-chip ${networkFocus.includes(kind) ? "active" : ""}`}
                  onClick={() => toggleNetworkFocus(kind)}
                >
                  {label}
                </button>
              ))}
            </div>
            <button
              type="button"
              className="graph-fullscreen-btn"
              onClick={() => graphRef.current?.exportJpg()}
            >
              Export
            </button>
            <button
              type="button"
              className="graph-fullscreen-btn"
              onClick={() => setGraphFullscreen((f) => !f)}
            >
              {graphFullscreen ? "✕ Exit" : "⛶ Expand"}
            </button>
          </div>
          {scopedNetworkGraph.nodes.length ? (
            <div className="network-board-shell">
              <div className="network-graph-stage">
                <TopologyGraph
                  ref={graphRef}
                  graph={scopedNetworkGraph}
                  activeNodeId={activeGraphNodeId}
                  theme={theme}
                  focusKinds={networkFocus}
                  onNodeSelect={(nodeId) => {
                    const nextKey = findNetworkInventoryKey(filteredNetworkInventory, nodeId);
                    if (nextKey) {
                      setSelectedNetworkKey(nextKey);
                    }
                  }}
                />
              </div>
            </div>
          ) : (
            <div className="detail-item">
              <p>No graphable relationships were found for this selection.</p>
            </div>
          )}
        </div>
      ) : activeTab === "nsgs" ? (
        <div className="detail-block">
          <div className="network-filter-bar">
            <select
              className="network-filter-select"
              value={nsgSearchMode}
              onChange={(event) => setNsgSearchMode(event.target.value)}
            >
              <option value="vnet">Attached to VNet</option>
              <option value="name">NSG Name</option>
              <option value="nic">Attached to NIC</option>
              <option value="subnet">In Subnet</option>
            </select>
            <input
              className="network-filter-input"
              type="search"
              value={nsgQuery}
              onChange={(event) => setNsgQuery(event.target.value)}
              placeholder="Filter NSGs"
            />
          </div>
          {filteredNetworkSecurityGroups.length ? (
            <div className="network-resource-list">
              {filteredNetworkSecurityGroups.map((group) => {
                const isExpanded = Boolean(expandedNsgs[group.id]);
                return (
                  <div key={group.id} className="network-resource-card">
                    <button
                      type="button"
                      className="network-resource-header"
                      onClick={() =>
                        setExpandedNsgs((current) => ({
                          ...current,
                          [group.id]: !current[group.id],
                        }))
                      }
                    >
                      <span className="network-resource-title-block">
                        <strong>{group.name || "Unnamed NSG"}</strong>
                        <span>{group.subscription_name} • {group.region || "Unknown region"}</span>
                      </span>
                      <span className="network-resource-meta">
                        <span className="badge">{pluralize(group.rule_count, "rule")}</span>
                        <span className="network-resource-toggle">{isExpanded ? "Hide" : "Show"}</span>
                      </span>
                    </button>
                    {isExpanded ? (
                      <div className="network-resource-body">
                        <div className="detail-item network-resource-summary-box">
                          <p className="mono long-id">{group.id}</p>
                          <div className="network-resource-inline-grid">
                            <div className="network-resource-inline-block">
                              <h4>Attached Subnets</h4>
                              {group.attached_subnets.length ? (
                                <div className="network-resource-inline-list horizontal">
                                  {group.attached_subnets.map((subnet) => (
                                    <p key={subnet.id}>
                                      <strong>{subnet.name}</strong>
                                      <span>{subnet.virtual_network_name} • {subnet.address_prefix || "No prefix"}</span>
                                    </p>
                                  ))}
                                </div>
                              ) : (
                                <p className="network-resource-empty">No attached subnets recorded.</p>
                              )}
                            </div>
                            <div className="network-resource-inline-block">
                              <h4>Attached NICs</h4>
                              {group.attached_nics.length ? (
                                <div className="network-resource-inline-list horizontal">
                                  {group.attached_nics.map((nic) => (
                                    <p key={nic.id}>
                                      <strong>{nic.name}</strong>
                                      <span>{nic.attached_resource_name || nic.attached_resource_type || "Attached resource"} • {nic.private_ip || "No private IP"}</span>
                                    </p>
                                  ))}
                                </div>
                              ) : (
                                <p className="network-resource-empty">No attached NICs recorded.</p>
                              )}
                            </div>
                          </div>
                        </div>
                        {group.security_rules.length ? (
                          <div className="network-resource-table">
                            <ExportCsvButton
                              columns={NSG_RULE_COLUMNS.map((col) => col.label)}
                              rows={group.security_rules}
                              getCell={nsgRuleCell}
                              filename={`${group.name}_security_rules`}
                            />
                            <div className="network-resource-table-head">
                              <span>Name</span>
                              <span>Priority</span>
                              <span>Direction</span>
                              <span>Access</span>
                              <span>Protocol</span>
                              <span>Flow</span>
                            </div>
                            {group.security_rules.map((rule) => {
                              const flow = `${formatRuleSource(rule)}:${formatRuleSourcePorts(rule)} -> ${formatRuleDestination(rule)}:${formatRuleDestinationPorts(rule)}`;
                              return (
                                <div key={rule.id || rule.name} className="network-resource-table-row">
                                  <span>{rule.name || "Unnamed rule"}</span>
                                  <span>{rule.priority || "?"}</span>
                                  <span>{rule.direction || "?"}</span>
                                  <span>{rule.access || "?"}</span>
                                  <span>{rule.protocol || "*"}</span>
                                  <span title={flow}>{flow}</span>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <div className="detail-item">
                            <p>No security rules recorded for this NSG.</p>
                          </div>
                        )}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : networkSecurityGroups.length ? (
            <div className="detail-item">
              <p>No NSGs match this filter.</p>
            </div>
          ) : (
            <div className="detail-item">
              <p>No network security groups recorded in this model.</p>
            </div>
          )}
        </div>
      ) : activeTab === "routes" ? (
        <div className="detail-block">
          {networkRouteTables.length ? (
            <div className="network-resource-list">
              {networkRouteTables.map((routeTable) => {
                const isExpanded = Boolean(expandedRouteTables[routeTable.id]);
                return (
                  <div key={routeTable.id} className="network-resource-card">
                    <button
                      type="button"
                      className="network-resource-header"
                      onClick={() =>
                        setExpandedRouteTables((current) => ({
                          ...current,
                          [routeTable.id]: !current[routeTable.id],
                        }))
                      }
                    >
                      <span className="network-resource-title-block">
                        <strong>{routeTable.name || "Unnamed route table"}</strong>
                        <span>{routeTable.subscription_name} • {routeTable.region || "Unknown region"}</span>
                      </span>
                      <span className="network-resource-meta">
                        <span className="badge">{pluralize(routeTable.route_count, "route")}</span>
                        <span className="network-resource-toggle">{isExpanded ? "Hide" : "Show"}</span>
                      </span>
                    </button>
                    {isExpanded ? (
                      <div className="network-resource-body">
                        <div className="detail-item">
                          <p>
                            BGP propagation: {routeTable.disable_bgp_route_propagation ? "Disabled" : "Enabled"}
                          </p>
                          <p className="mono long-id">{routeTable.id}</p>
                        </div>
                        {routeTable.routes.length ? (
                          <div className="network-resource-table">
                            <ExportCsvButton
                              columns={ROUTE_COLUMNS.map((col) => col.label)}
                              rows={routeTable.routes}
                              getCell={(row, label) => row[ROUTE_COLUMNS.find((col) => col.label === label).key]}
                              filename={`${routeTable.name}_routes`}
                            />
                            <div className="network-resource-table-head network-resource-table-row-routes">
                              <span>Name</span>
                              <span>Prefix</span>
                              <span>Next Hop</span>
                              <span>Next Hop IP</span>
                            </div>
                            {routeTable.routes.map((route) => (
                              <div key={route.id || route.name} className="network-resource-table-row network-resource-table-row-routes">
                                <span>{route.name || "Unnamed route"}</span>
                                <span>{route.address_prefix || "*"}</span>
                                <span>{route.next_hop_type || "Unknown"}</span>
                                <span>{route.next_hop_ip_address || "n/a"}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="detail-item">
                            <p>No routes recorded for this route table.</p>
                          </div>
                        )}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="detail-item">
              <p>No route tables recorded in this model.</p>
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="network-focus-summary">
            <div className="fact-card">
              <span>Public IPs</span>
              <strong>{networkFocusSummary.publicIp}</strong>
            </div>
            <div className="fact-card">
              <span>Subnets</span>
              <strong>{networkFocusSummary.subnet}</strong>
            </div>
            <div className="fact-card">
              <span>Internet Facing</span>
              <strong>{networkFocusSummary.internetFacing}</strong>
            </div>
            <div className="fact-card">
              <span>Peerings</span>
              <strong>{networkFocusSummary.peering}</strong>
            </div>
          </div>
          <div className="facts-grid network-facts-grid">
            {Object.entries(selectedNetworkItem.data)
              .filter(([key, value]) => key !== "id" && key !== "name" && key !== "subscriptions" && value !== null && value !== undefined)
              .map(([key, value]) => (
                <div key={key} className="fact-card">
                  <span>{key.replace(/_/g, " ")}</span>
                  <strong>{formatFactValue(value)}</strong>
                </div>
              ))}
          </div>
          {selectedNetworkItem.kind === "general" ? (
            <div className="detail-block">
              <h3>Subscriptions</h3>
              {selectedNetworkItem.data.subscriptions.length ? (
                <div className="network-subscription-list">
                  {selectedNetworkItem.data.subscriptions.map((subscription) => (
                    <div key={subscription.id} className="detail-item network-subscription-item">
                      <strong title={subscription.name}>{subscription.name}</strong>
                      <p>
                        {subscription.state} • {pluralize(subscription.vnetCount, "vnet")} • {pluralize(subscription.subnetCount, "subnet")} • {pluralize(subscription.publicIpCount, "public IP")}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="detail-item">
                  <p>No subscriptions recorded in this model.</p>
                </div>
              )}
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}
