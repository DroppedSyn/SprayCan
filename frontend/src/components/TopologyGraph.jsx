import { forwardRef, useEffect, useImperativeHandle, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import fcose from "cytoscape-fcose";

cytoscape.use(dagre);
cytoscape.use(fcose);

// Info icon drawn in each node's top-right corner. Sizes are in graph units, so the icon
// scales with zoom and hit-testing can use the node's model bounding box.
const INFO_ICON_SIZE = 14;
const INFO_ICON_INSET = 5;

function infoIconUri(isDark) {
  const stroke = isDark ? "#b9d3ea" : "#3d5f7a";
  const fill = isDark ? "#14243a" : "#ffffff";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 28 28">`
    + `<circle cx="14" cy="14" r="12" fill="${fill}" stroke="${stroke}" stroke-width="2.4"/>`
    + `<circle cx="14" cy="8.6" r="1.9" fill="${stroke}"/>`
    + `<rect x="12.2" y="12" width="3.6" height="9.4" rx="1.6" fill="${stroke}"/></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// Centre of a node's info icon, in model coordinates.
function infoIconCenter(node) {
  const box = node.boundingBox({ includeLabels: false, includeOverlays: false, includeUnderlays: false, includeOutlines: false });
  const border = parseFloat(node.style("border-width")) || 0;
  const offset = border + INFO_ICON_INSET + INFO_ICON_SIZE / 2;
  return { x: box.x2 - offset, y: box.y1 + offset };
}

function isOnInfoIcon(node, position) {
  const center = infoIconCenter(node);
  const reach = INFO_ICON_SIZE / 2 + 3;
  return Math.abs(position.x - center.x) <= reach && Math.abs(position.y - center.y) <= reach;
}

// The node (the tapped one or a box containing it) whose info icon is under the pointer.
function infoNodeAt(target, position) {
  if (!target || !target.isNode || !target.isNode()) return null;
  return [target, ...target.ancestors()].find((node) => isOnInfoIcon(node, position)) || null;
}

const POPOVER_WIDTH = 300;
const POPOVER_GAP = 56;

function InfoPopover({ cy, container, nodeId, info, onClose }) {
  const popoverRef = useRef(null);
  const [height, setHeight] = useState(200);
  const [, setTick] = useState(0);

  // Follow the node while the graph is panned, zoomed or re-laid out, and the page resized.
  useEffect(() => {
    let frame = 0;
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => setTick((tick) => tick + 1));
    };
    cy.on("viewport position", update);
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      cancelAnimationFrame(frame);
      cy.removeListener("viewport position", update);
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [cy]);

  useLayoutEffect(() => {
    if (popoverRef.current) setHeight(popoverRef.current.offsetHeight);
  });

  const node = cy.getElementById(nodeId);
  if (!node.length || !info) return null;

  const rect = container.getBoundingClientRect();
  const zoom = cy.zoom();
  const pan = cy.pan();
  const center = infoIconCenter(node);
  const anchor = { x: rect.left + center.x * zoom + pan.x, y: rect.top + center.y * zoom + pan.y };
  const anchorVisible = anchor.x >= rect.left && anchor.x <= rect.right && anchor.y >= rect.top && anchor.y <= rect.bottom;

  const margin = 8;
  let left = anchor.x + POPOVER_GAP;
  if (left + POPOVER_WIDTH > window.innerWidth - margin) left = anchor.x - POPOVER_GAP - POPOVER_WIDTH;
  left = Math.max(margin, Math.min(left, window.innerWidth - POPOVER_WIDTH - margin));
  const top = Math.max(margin, Math.min(anchor.y - 28, window.innerHeight - height - margin));
  const lineEnd = {
    x: Math.max(left, Math.min(anchor.x, left + POPOVER_WIDTH)),
    y: Math.max(top, Math.min(anchor.y, top + height)),
  };

  return createPortal(
    <>
      {anchorVisible ? (
        <svg className="graph-info-line" aria-hidden="true">
          <line x1={anchor.x} y1={anchor.y} x2={lineEnd.x} y2={lineEnd.y} />
          <circle cx={anchor.x} cy={anchor.y} r="4" />
        </svg>
      ) : null}
      <div
        ref={popoverRef}
        className="graph-info-popover"
        role="dialog"
        aria-label={`${info.kind}: ${info.title}`}
        style={{ left, top, width: POPOVER_WIDTH }}
      >
        <div className="graph-info-header">
          <div>
            <p className="graph-info-kind">{info.kind}</p>
            <h4 className="graph-info-title">{info.title}</h4>
          </div>
          <button type="button" className="graph-info-close" aria-label="Close" onClick={onClose}>×</button>
        </div>
        <dl className="graph-info-rows">
          {info.rows.map(([label, value]) => (
            <div key={label} className="graph-info-row">
              <dt>{label}</dt>
              <dd className={label.endsWith("ID") ? "mono" : undefined}>{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </>,
    document.body,
  );
}

function buildGraphStyle(isDark) {
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        shape: "round-rectangle",
        width: 168,
        height: 48,
        "background-color": isDark ? "#20343a" : "#eaf1f1",
        "border-width": 1.4,
        "border-color": isDark ? "#90aab0" : "#6d858d",
        color: isDark ? "#e4f0ef" : "#142126",
        "font-size": 11,
        "font-weight": 700,
        "text-wrap": "wrap",
        // Leaves room on both sides for the info icon (168 - 2 * (inset + icon + 3)).
        "text-max-width": 124,
        "text-overflow-wrap": "anywhere",
        "text-valign": "center",
        "text-halign": "center",
        "background-image": infoIconUri(isDark),
        "background-width": INFO_ICON_SIZE,
        "background-height": INFO_ICON_SIZE,
        "background-fit": "none",
        "background-clip": "none",
        "background-image-containment": "over",
        "background-position-x": "100%",
        "background-position-y": "0%",
        "background-offset-x": -INFO_ICON_INSET,
        "background-offset-y": INFO_ICON_INSET,
        "background-image-opacity": 0.9,
      },
    },
    {
      selector: "node.hide-info-icon",
      style: { "background-image-opacity": 0 },
    },
    {
      selector: "edge",
      style: {
        width: 2,
        "line-color": isDark ? "#6f8b92" : "#8da2a8",
        "target-arrow-color": isDark ? "#6f8b92" : "#8da2a8",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
      },
    },
    {
      selector: ".muted",
      style: {
        opacity: 0.16,
      },
    },
    {
      selector: 'node[tone = "subscription"]',
      style: {
        "background-color": isDark ? "#21435f" : "#dbe7f3",
        "border-color": isDark ? "#7eaee0" : "#355f86",
      },
    },
    {
      selector: 'node[tone = "vnet"]',
      style: {
        "background-color": isDark ? "#1d4f4a" : "#d9ebe8",
        "border-color": isDark ? "#65c8ad" : "#1f7a72",
      },
    },
    {
      selector: 'node[tone = "subnet"]',
      style: {
        "background-color": isDark ? "#1d473d" : "#dcebe6",
        "border-color": isDark ? "#65c8ad" : "#23705e",
      },
    },
    {
      selector: 'node[tone = "device"]',
      style: {
        "background-color": isDark ? "#4d4020" : "#efe4c8",
        "border-color": isDark ? "#d5ad4f" : "#8b6400",
      },
    },
    {
      selector: 'node[tone = "deviceExposed"]',
      style: {
        "background-color": isDark ? "#523020" : "#f0ddcf",
        "border-color": isDark ? "#f0b36b" : "#b8681e",
      },
    },
    {
      selector: 'node[tone = "publicIp"]',
      style: {
        "background-color": isDark ? "#4a2941" : "#efd7e5",
        "border-color": isDark ? "#e196c2" : "#a6487f",
      },
    },
    {
      selector: 'node[tone = "peering"]',
      style: {
        "background-color": isDark ? "#49355b" : "#e7dcf0",
        "border-color": isDark ? "#c19ae0" : "#7c4f95",
      },
    },
    {
      selector: 'node[tone = "vwan"]',
      style: {
        "background-color": isDark ? "#253b58" : "#dbe3f2",
        "border-color": isDark ? "#8ca9d8" : "#4d6f8f",
      },
    },
    {
      selector: 'node[tone = "hub"]',
      style: {
        "background-color": isDark ? "#274854" : "#dae9ef",
        "border-color": isDark ? "#7fb2c4" : "#3c7385",
      },
    },
    {
      selector: 'node[tone = "routeServer"]',
      style: {
        "background-color": isDark ? "#3a3a54" : "#e3e2f2",
        "border-color": isDark ? "#9a97d8" : "#5b57a3",
      },
    },
    {
      selector: 'node[tone = "surface"]',
      style: {
        "background-color": isDark ? "#5b2f2f" : "#f0d8d8",
        "border-color": isDark ? "#e39a9a" : "#9d4f4f",
      },
    },
    {
      selector: "node.active",
      style: {
        "border-width": 3,
        "border-color": isDark ? "#55b8ae" : "#1f7a72",
      },
    },
    {
      selector: ":compound",
      style: {
        // Box titles sit above the box, clear of the info icon: keep them on one line.
        "text-max-width": 1000,
        "text-overflow-wrap": "whitespace",
        "text-valign": "top",
        "text-halign": "center",
        "padding": "30px",
        "font-size": 12,
        "font-weight": 700,
        "background-opacity": 0.3,
      },
    },
    {
      // NSG: a frosted-glass pane around the subnet it protects. After ":compound"
      // so it wins over the generic compound padding and fill.
      selector: 'node[tone = "nsg"]',
      style: {
        "background-fill": "linear-gradient",
        "background-gradient-direction": "to-bottom-right",
        "background-gradient-stop-colors": isDark ? "#c9e4ff #6c8fb3" : "#ffffff #b9d6ee",
        "background-gradient-stop-positions": "0 100",
        "background-opacity": isDark ? 0.14 : 0.5,
        "border-width": 1.5,
        "border-color": isDark ? "#cfe6ff" : "#ffffff",
        "border-opacity": isDark ? 0.45 : 0.95,
        "outline-width": 1,
        "outline-color": isDark ? "#7fa6c9" : "#7d9db8",
        "outline-opacity": isDark ? 0.5 : 0.55,
        "outline-offset": 0,
        padding: "24px",
        "font-size": 10,
        "font-weight": 600,
        color: isDark ? "#b9d3ea" : "#3d5f7a",
        "text-valign": "top",
        "text-margin-y": -3,
      },
    },
    {
      selector: 'node[tone = "nsg"].active',
      style: {
        "outline-width": 2.5,
        "outline-color": isDark ? "#55b8ae" : "#1f7a72",
        "outline-opacity": 1,
      },
    },
  ];
}

function buildElements(graph) {
  const nodeElements = (graph?.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      tone: node.tone || node.lane,
      ...(node.parent ? { parent: node.parent } : {}),
      ...(node.ref ? { ref: node.ref } : {}),
    },
  }));

  const edgeElements = (graph?.edges || []).map((edge) => ({
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
    },
  }));

  return [...nodeElements, ...edgeElements];
}

const TopologyGraph = forwardRef(function TopologyGraph({ graph, activeNodeId = "", describeNode, theme = "light", focusKinds = [] }, ref) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [infoTarget, setInfoTarget] = useState(null); // { id, ref } of the node whose info is open
  const isDark = theme === "dark";

  useImperativeHandle(ref, () => ({
    exportJpg() {
      const cy = cyRef.current;
      if (!cy) return;
      cy.nodes().addClass("hide-info-icon");
      const uri = cy.jpg({ quality: 0.95, full: true });
      cy.nodes().removeClass("hide-info-icon");
      const a = document.createElement("a");
      a.href = uri;
      a.download = "topology.jpg";
      a.click();
    },
  }));

  useEffect(() => {
    if (!containerRef.current) {
      return undefined;
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      userPanningEnabled: true,
      userZoomingEnabled: true,
      minZoom: 0.2,
      maxZoom: 3.5,
      boxSelectionEnabled: false,
      autoungrabify: false,
      autolock: false,
      wheelSensitivity: 0.45,
      style: buildGraphStyle(isDark),
    });

    // Only the info icon is interactive: tapping it opens the info popover, tapping empty
    // space closes it. Glass NSG boxes carry the NSG resource id in `ref`.
    cy.on("tap", (event) => {
      if (event.target === cy) {
        setInfoTarget(null);
        return;
      }
      const node = infoNodeAt(event.target, event.position);
      if (node) setInfoTarget({ id: node.id(), ref: node.data("ref") || "" });
    });
    let pointerOverIcon = false;
    cy.on("mousemove", (event) => {
      const overIcon = event.target !== cy && Boolean(infoNodeAt(event.target, event.position));
      if (overIcon !== pointerOverIcon) {
        pointerOverIcon = overIcon;
        containerRef.current.style.cursor = overIcon ? "pointer" : "";
      }
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // Created once; the theme is applied by the effect below without a rebuild or re-layout.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    cyRef.current?.style(buildGraphStyle(isDark));
  }, [isDark]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    setInfoTarget(null);
    cy.elements().remove();
    cy.add(buildElements(graph));

    if (graph?.layout === "fcose") {
      // fcose estimates compound node sizes before the DOM has measured them.
      // Two-pass approach: first pass positions the graph; second short pass
      // refines using the actual rendered compound sizes cytoscape now knows.
      const fcoseBase = {
        name: "fcose",
        animate: false,
        fit: true,
        padding: 40,
        nodeSeparation: 140,
        idealEdgeLength: 240,
        // Compound (parent) nodes need much higher repulsion than leaf nodes
        // so VNet/VWAN boxes don't crowd each other.
        nodeRepulsion: (node) => (node.isParent() ? 55000 : 8000),
        numIter: 3000,
        tile: true,
        tilingPaddingVertical: 50,
        tilingPaddingHorizontal: 50,
        uniformNodeDimensions: false,
        packComponents: true,
        sampleSize: 100,
        gravity: 0.20,
        gravityRange: 3.8,
        gravityCompound: 1.0,
        gravityRangeCompound: 1.5,
        nestingFactor: 0.5,
      };

      const firstPass = cy.layout(fcoseBase);
      firstPass.on("layoutstop", () => {
        // Short refinement pass — compound sizes are now accurate.
        cy.layout({ ...fcoseBase, randomize: false, numIter: 800, initialEnergyOnIncremental: 0.5 }).run();
        cy.fit(undefined, 24);
      });
      firstPass.run();
    } else {
      cy.layout({
        name: "dagre",
        rankDir: "LR",
        ranker: "network-simplex",
        nodeSep: 40,
        rankSep: 120,
        edgeSep: 10,
        padding: 20,
        animate: false,
        fit: true,
      }).run();

      cy.fit(undefined, 12);
      cy.zoom({
        level: Math.min(cy.maxZoom(), cy.zoom() * 1.18),
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
    }
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    cy.nodes().removeClass("active");
    cy.elements().removeClass("muted");

    const kinds = new Set(focusKinds);
    if (kinds.has("device")) kinds.add("deviceExposed");
    const focusNodes = kinds.size ? cy.nodes().filter((node) => kinds.has(node.data("tone"))) : cy.collection();
    // A kind this view doesn't draw (e.g. Public IPs in Topology) matches nothing: dim nothing.
    if (focusNodes.length) {
      // Keep the boxes that contain focused nodes visible: a muted parent dims its children too.
      const focusNeighborhood = focusNodes.closedNeighborhood();
      cy.elements().not(focusNeighborhood.union(focusNeighborhood.ancestors())).addClass("muted");
    }

    if (!activeNodeId) {
      return;
    }

    // An NSG appears as one glass box per subnet; highlight all of them.
    const activeNodes = cy.getElementById(activeNodeId).union(
      cy.nodes().filter((node) => node.data("ref") === activeNodeId),
    );
    activeNodes.addClass("active");
  }, [activeNodeId, focusKinds]);

  useEffect(() => {
    const container = containerRef.current;
    const cy = cyRef.current;
    if (!container || !cy || typeof ResizeObserver === "undefined") {
      return undefined;
    }

    const observer = new ResizeObserver(() => {
      cy.resize();
      cy.fit(undefined, 12);
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, [graph]);

  useEffect(() => {
    if (!infoTarget) return undefined;
    // Capture phase, and stop it: an open popover consumes Escape, so the fullscreen graph's
    // own Escape listener (TopologyDetailPane) doesn't also fire.
    const onKey = (event) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      setInfoTarget(null);
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [infoTarget]);

  const info = infoTarget && describeNode ? describeNode(infoTarget.id, infoTarget.ref) : null;

  return (
    <div style={{ position: "relative", flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div ref={containerRef} className="network-cytoscape" />
      {infoTarget && cyRef.current && containerRef.current ? (
        <InfoPopover
          cy={cyRef.current}
          container={containerRef.current}
          nodeId={infoTarget.id}
          info={info}
          onClose={() => setInfoTarget(null)}
        />
      ) : null}
    </div>
  );
});

export default TopologyGraph;
