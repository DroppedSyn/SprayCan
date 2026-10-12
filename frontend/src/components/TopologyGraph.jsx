import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import fcose from "cytoscape-fcose";

cytoscape.use(dagre);
cytoscape.use(fcose);

function buildElements(graph) {
  const nodeElements = (graph?.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      tone: node.tone || node.lane,
      ...(node.parent ? { parent: node.parent } : {}),
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

const TopologyGraph = forwardRef(function TopologyGraph({ graph, activeNodeId = "", onNodeSelect, theme = "light", focusKinds = [] }, ref) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const onNodeSelectRef = useRef(onNodeSelect);
  const isDark = theme === "dark";

  useImperativeHandle(ref, () => ({
    exportJpg() {
      const cy = cyRef.current;
      if (!cy) return;
      const uri = cy.jpg({ quality: 0.95, full: true });
      const a = document.createElement("a");
      a.href = uri;
      a.download = "topology.jpg";
      a.click();
    },
  }));

  useEffect(() => {
    onNodeSelectRef.current = onNodeSelect;
  }, [onNodeSelect]);

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
      style: [
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
            "text-max-width": 136,
            "text-valign": "center",
            "text-halign": "center",
          },
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
          selector: 'node[tone = "nsg"]',
          style: {
            width: 110,
            height: 28,
            "font-size": 9,
            "font-weight": 600,
            "background-color": isDark ? "#3a3520" : "#f0ebd2",
            "border-color": isDark ? "#c4a93a" : "#8b7200",
            "border-width": 1,
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
            "text-valign": "top",
            "text-halign": "center",
            "padding": "30px",
            "font-size": 12,
            "font-weight": 700,
            "background-opacity": 0.3,
          },
        },
      ],
    });

    cy.on("tap", "node", (event) => {
      onNodeSelectRef.current?.(event.target.id());
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [isDark]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

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
        cy.layout({ ...fcoseBase, numIter: 800, initialEnergyOnIncremental: 0.5 }).run();
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

    if (focusKinds.length) {
      const focusNodes = cy.nodes().filter((node) => focusKinds.includes(node.data("tone")));
      const focusNeighborhood = focusNodes.closedNeighborhood();
      cy.elements().not(focusNeighborhood).addClass("muted");
    }

    if (!activeNodeId) {
      return;
    }

    const activeNode = cy.getElementById(activeNodeId);
    if (activeNode.length) {
      activeNode.addClass("active");
    }
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

  return (
    <div style={{ position: "relative", flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div ref={containerRef} className="network-cytoscape" />
    </div>
  );
});

export default TopologyGraph;
