export function normalizeNetworkModel(payload) {
  if (payload && !Array.isArray(payload) && Array.isArray(payload.subscriptions)) {
    return payload;
  }
  return null;
}

export function pluralize(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

// Azure puts a rule's address/port scope in the singular field, the plural list
// (multiple prefixes, "80,443"-style ports) or ASGs. Reading only the singular field
// renders a scoped rule as "*", i.e. as open to any. An explicit "any" is always
// stored as a literal "*", so an empty scope is never shown as "*".
function resourceNameFromId(id) {
  return String(id || "").split("/").filter(Boolean).pop() || id;
}

function ruleScope(single, list, asgIds) {
  const parts = [
    ...(single ? [single] : []),
    ...(list || []),
    ...(asgIds || []).map((id) => `ASG:${resourceNameFromId(id)}`),
  ];
  if (parts.length) return parts.join(", ");
  // Model files written before the plural/ASG fields existed don't carry them.
  return list === undefined ? "Not recorded (older model file)" : "Not recorded";
}

export function formatRuleSource(rule) {
  return ruleScope(rule.source_address_prefix, rule.source_address_prefixes, rule.source_application_security_group_ids);
}

export function formatRuleDestination(rule) {
  return ruleScope(
    rule.destination_address_prefix,
    rule.destination_address_prefixes,
    rule.destination_application_security_group_ids,
  );
}

export function formatRuleSourcePorts(rule) {
  return ruleScope(rule.source_port_range, rule.source_port_ranges);
}

export function formatRuleDestinationPorts(rule) {
  return ruleScope(rule.destination_port_range, rule.destination_port_ranges);
}

// Generic fact-card rendering: lists of objects (security rules, routes, subnets...)
// show as their names rather than "[object Object]".
export function formatFactValue(value) {
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    if (value.every((item) => item === null || typeof item !== "object")) return value.join(", ");
    const names = value.map((item) => item?.name || resourceNameFromId(item?.id)).filter(Boolean);
    return `${value.length} item${value.length === 1 ? "" : "s"}${names.length ? `: ${names.join(", ")}` : ""}`;
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function summarizeNetworkSubscriptions(model) {
  return (model?.subscriptions || []).map((subscription) => ({
    id: subscription.id,
    name: subscription.name,
    state: subscription.state || "Unknown state",
    vnetCount: (subscription.virtual_networks || []).length,
    subnetCount: (subscription.virtual_networks || []).reduce(
      (count, vnet) => count + (vnet.subnets || []).length,
      0,
    ),
    publicIpCount: (subscription.public_ip_addresses || []).length,
  }));
}

export function summarizeNetworkSecurityGroups(model) {
  return (model?.subscriptions || []).flatMap((subscription) => {
    const subnetAttachments = new Map();
    const nicAttachments = new Map();

    for (const vnet of subscription.virtual_networks || []) {
      for (const subnet of vnet.subnets || []) {
        if (subnet.network_security_group_id) {
          if (!subnetAttachments.has(subnet.network_security_group_id)) {
            subnetAttachments.set(subnet.network_security_group_id, []);
          }
          subnetAttachments.get(subnet.network_security_group_id).push({
            id: subnet.id,
            name: subnet.name,
            address_prefix: subnet.address_prefix || (subnet.address_prefixes || []).join(", "),
            virtual_network_name: vnet.name,
          });
        }

        for (const device of subnet.connected_devices || []) {
          if (device.network_security_group_id) {
            if (!nicAttachments.has(device.network_security_group_id)) {
              nicAttachments.set(device.network_security_group_id, []);
            }
            nicAttachments.get(device.network_security_group_id).push({
              id: device.network_interface_id || device.id,
              name: device.network_interface_name || device.name,
              attached_resource_name: device.name,
              attached_resource_type: device.type,
              private_ip: device.private_ip,
            });
          }
        }
      }
    }

    return (subscription.network_security_groups || []).map((group) => ({
      ...group,
      subscription_id: subscription.id,
      subscription_name: subscription.name,
      rule_count: (group.security_rules || []).length,
      attached_subnets: subnetAttachments.get(group.id) || [],
      attached_nics: nicAttachments.get(group.id) || [],
    }));
  });
}

export function summarizeNetworkRouteTables(model) {
  return (model?.subscriptions || []).flatMap((subscription) =>
    (subscription.route_tables || []).map((routeTable) => ({
      ...routeTable,
      subscription_id: subscription.id,
      subscription_name: subscription.name,
      route_count: (routeTable.routes || []).length,
    })),
  );
}

export function summarizeNetworkOverview(model) {
  const subscriptions = summarizeNetworkSubscriptions(model);
  const overview = {
    subscriptionCount: subscriptions.length,
    vnetCount: 0,
    subnetCount: 0,
    publicIpCount: 0,
    deviceCount: 0,
    peeringCount: 0,
    internetFacingCount: 0,
    subscriptions,
  };

  for (const subscription of model?.subscriptions || []) {
    overview.publicIpCount += (subscription.public_ip_addresses || []).length;
    overview.vnetCount += (subscription.virtual_networks || []).length;
    for (const vnet of subscription.virtual_networks || []) {
      overview.peeringCount += (vnet.peerings || []).length;
      overview.subnetCount += (vnet.subnets || []).length;
      for (const subnet of vnet.subnets || []) {
        overview.deviceCount += (subnet.connected_devices || []).length;
        for (const device of subnet.connected_devices || []) {
          if (device.public_ip_id || device.public_ip_address) {
            overview.internetFacingCount += 1;
          }
        }
      }
    }
  }

  return overview;
}

export function buildNetworkInventory(model) {
  const overview = summarizeNetworkOverview(model);
  const items = [
    {
      key: "general:overview",
      kind: "general",
      title: "General",
      meta: `${pluralize(overview.subscriptionCount, "subscription")} • ${pluralize(overview.vnetCount, "vnet")} • ${pluralize(overview.subnetCount, "subnet")}`,
      data: overview,
    },
  ];
  for (const subscription of model?.subscriptions || []) {
    const subscriptionKey = `subscription:${subscription.id}`;
    items.push({
      key: subscriptionKey,
      kind: "subscription",
      title: subscription.name,
      meta: `${subscription.state || "Unknown state"} • ${pluralize((subscription.public_ip_addresses || []).length, "public IP")}`,
      data: subscription,
    });
    for (const virtualWan of subscription.virtual_wans || []) {
      items.push({
        key: `vwan:${virtualWan.id}`,
        kind: "vwan",
        title: virtualWan.name,
        meta: `${virtualWan.region || "Unknown region"} • ${pluralize((virtualWan.virtual_hubs || []).length, "hub")}`,
        data: { ...virtualWan, subscription_name: subscription.name },
      });
      for (const virtualHub of virtualWan.virtual_hubs || []) {
        items.push({
          key: `hub:${virtualHub.id}`,
          kind: "hub",
          title: virtualHub.name,
          meta: `${virtualHub.region || "Unknown region"} • ${virtualHub.address_prefix || "No prefix"}`,
          data: { ...virtualHub, virtual_wan_name: virtualWan.name, subscription_name: subscription.name },
        });
      }
    }
    for (const virtualHub of subscription.orphaned_virtual_hubs || []) {
      items.push({
        key: `hub:${virtualHub.id}`,
        kind: "hub",
        title: virtualHub.name,
        meta: `${virtualHub.region || "Unknown region"} • ${virtualHub.address_prefix || "No prefix"}`,
        data: { ...virtualHub, subscription_name: subscription.name },
      });
    }
    for (const routeServer of subscription.route_servers || []) {
      items.push({
        key: `routeServer:${routeServer.id}`,
        kind: "routeServer",
        title: routeServer.name,
        meta: `${routeServer.region || "Unknown region"} • ${pluralize((routeServer.router_ips || []).length, "router IP")}`,
        data: { ...routeServer, subscription_name: subscription.name },
      });
    }
    for (const networkSecurityGroup of subscription.network_security_groups || []) {
      items.push({
        key: `nsg:${networkSecurityGroup.id}`,
        kind: "nsg",
        title: networkSecurityGroup.name,
        meta: `${networkSecurityGroup.region || "Unknown region"} • ${pluralize((networkSecurityGroup.security_rules || []).length, "rule")}`,
        data: { ...networkSecurityGroup, subscription_name: subscription.name },
      });
    }
    for (const routeTable of subscription.route_tables || []) {
      items.push({
        key: `routeTable:${routeTable.id}`,
        kind: "routeTable",
        title: routeTable.name,
        meta: `${routeTable.region || "Unknown region"} • ${pluralize((routeTable.routes || []).length, "route")}`,
        data: { ...routeTable, subscription_name: subscription.name },
      });
    }
    for (const publicIp of subscription.public_ip_addresses || []) {
      items.push({
        key: `publicIp:${publicIp.id}`,
        kind: "publicIp",
        title: publicIp.name || publicIp.ip_address || "Public IP",
        meta: publicIp.ip_address || publicIp.fqdn || "No address",
        data: { ...publicIp, subscription_name: subscription.name },
      });
    }
    for (const vnet of subscription.virtual_networks || []) {
      const vnetKey = `vnet:${vnet.id}`;
      items.push({
        key: vnetKey,
        kind: "vnet",
        title: vnet.name,
        meta: `${vnet.region || "Unknown region"} • ${(vnet.address_spaces || []).join(", ") || "No address space"}`,
        data: { ...vnet, subscription_name: subscription.name },
      });
      for (const subnet of vnet.subnets || []) {
        const subnetKey = `subnet:${subnet.id}`;
        items.push({
          key: subnetKey,
          kind: "subnet",
          title: subnet.name,
          meta: subnet.address_prefix || (subnet.address_prefixes || []).join(", ") || "No prefix",
          data: { ...subnet, virtual_network_name: vnet.name, subscription_name: subscription.name },
        });
        for (const device of subnet.connected_devices || []) {
          items.push({
            key: `device:${subnet.id}:${device.id || device.network_interface_id || device.name}`,
            kind: "device",
            title: device.name || device.type,
            meta: `${device.type} • ${device.private_ip || "No private IP"}`,
            data: { ...device, subnet_name: subnet.name, virtual_network_name: vnet.name, subscription_name: subscription.name },
          });
        }
      }
      for (const peering of vnet.peerings || []) {
        items.push({
          key: `peering:${peering.id}`,
          kind: "peering",
          title: peering.name,
          meta: peering.state || "Unknown state",
          data: { ...peering, virtual_network_name: vnet.name, subscription_name: subscription.name },
        });
      }
    }
  }
  return items;
}

export function getNetworkSearchText(item) {
  return JSON.stringify(item || {}).toLowerCase();
}

export function groupNetworkInventory(items) {
  const order = ["general", "vwan", "hub", "routeServer", "vnet", "subnet", "device", "publicIp", "peering", "nsg", "routeTable", "subscription"];
  const labels = {
    general: "General",
    vwan: "Virtual WANs",
    hub: "Virtual Hubs",
    routeServer: "Route Servers",
    subscription: "Subscriptions",
    vnet: "Virtual Networks",
    subnet: "Subnets",
    device: "Connected Devices",
    publicIp: "Public IPs",
    peering: "Peerings",
    nsg: "NSGs",
    routeTable: "Route Tables",
  };

  return order
    .map((kind) => ({
      kind,
      label: labels[kind] || kind,
      items: items.filter((item) => item.kind === kind),
    }))
    .filter((group) => group.items.length);
}

export function summarizeNetworkFocus(model) {
  const summary = {
    subnet: 0,
    publicIp: 0,
    device: 0,
    internetFacing: 0,
    peering: 0,
  };

  for (const subscription of model?.subscriptions || []) {
    summary.publicIp += (subscription.public_ip_addresses || []).length;
    for (const vnet of subscription.virtual_networks || []) {
      summary.peering += (vnet.peerings || []).length;
      for (const subnet of vnet.subnets || []) {
        summary.subnet += 1;
        for (const device of subnet.connected_devices || []) {
          summary.device += 1;
          if (device.public_ip_id || device.public_ip_address) {
            summary.internetFacing += 1;
          }
        }
      }
    }
  }

  return summary;
}


function buildTopologyGraph(model) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const seenEdges = new Set();

  function addNode(id, label, tone, parent) {
    if (!id || seen.has(id)) return;
    seen.add(id);
    const node = { id, label, tone };
    if (parent) node.parent = parent;
    nodes.push(node);
  }

  function addEdge(source, target) {
    if (!source || !target) return;
    const key = [source, target].sort().join("|");
    if (seenEdges.has(key)) return;
    seenEdges.add(key);
    edges.push({ id: key, source, target });
  }

  // Build NSG id → name lookup from all subscriptions up front
  const nsgNameById = {};
  for (const subscription of model?.subscriptions || []) {
    for (const nsg of subscription.network_security_groups || []) {
      if (nsg.id && nsg.name) nsgNameById[nsg.id] = nsg.name;
    }
  }

  for (const subscription of model?.subscriptions || []) {
    // Virtual WANs as compound parents containing their hubs
    for (const vwan of subscription.virtual_wans || []) {
      if (!vwan.id) continue;
      addNode(vwan.id, vwan.name, "vwan");
      for (const hub of vwan.virtual_hubs || []) {
        if (!hub.id) continue;
        addNode(hub.id, hub.name, "hub", vwan.id);
      }
    }

    // Hubs not attached to a VWAN
    for (const hub of subscription.orphaned_virtual_hubs || []) {
      if (!hub.id) continue;
      addNode(hub.id, hub.name, "hub");
    }

    // Standalone Route Servers (virtualHubs with no parent WAN and no hub-vnet connections)
    for (const routeServer of subscription.route_servers || []) {
      if (!routeServer.id) continue;
      addNode(routeServer.id, routeServer.name, "routeServer");
    }

    // Hub → VNet connection edges
    for (const conn of subscription.virtual_hub_vnet_connections || []) {
      addEdge(conn.virtual_hub_id, conn.remote_virtual_network_id);
    }

    // VNets as compound parents containing their subnets
    for (const vnet of subscription.virtual_networks || []) {
      if (!vnet.id) continue;
      addNode(vnet.id, vnet.name, "vnet");

      for (const subnet of vnet.subnets || []) {
        if (!subnet.id) continue;
        const prefix = subnet.address_prefix || (subnet.address_prefixes || []).join(", ") || "";
        addNode(subnet.id, prefix ? `${subnet.name}\n${prefix}` : subnet.name, "subnet", vnet.id);

        // NSG badge inside the subnet compound node
        if (subnet.network_security_group_id) {
          const nsgName = nsgNameById[subnet.network_security_group_id]
            || subnet.network_security_group_id.split("/").filter(Boolean).pop();
          addNode(`${subnet.id}::nsg`, nsgName, "nsg", subnet.id);
        }
      }

      // Peering edges — add placeholder for cross-tenant remote VNets
      for (const peering of vnet.peerings || []) {
        const remoteId = peering.remote_virtual_network_id;
        if (!remoteId) continue;
        if (!seen.has(remoteId)) {
          const remoteName = remoteId.split("/").filter(Boolean).pop() || "remote";
          addNode(remoteId, remoteName, "peering");
        }
        addEdge(vnet.id, remoteId);
      }
    }
  }

  return { title: "Topology", layout: "fcose", nodes, edges };
}

function buildShapeGraph(model) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const connectedVnetIds = new Set();
  const publicIpToVnet = new Map();

  function addNode(id, lane, label, tone) {
    if (!id || seen.has(id)) {
      return;
    }
    seen.add(id);
    nodes.push({ id, lane, label, tone: tone || lane });
  }

  function addEdge(source, target) {
    if (!source || !target) {
      return;
    }
    edges.push({ source, target, id: `${source}:${target}` });
  }

  addNode("internet:surface", "internet", "Internet Surface", "surface");

  for (const subscription of model?.subscriptions || []) {
    for (const virtualWan of subscription.virtual_wans || []) {
      addNode(virtualWan.id, "vwan", virtualWan.name, "vwan");

      for (const virtualHub of virtualWan.virtual_hubs || []) {
        addNode(virtualHub.id, "hub", virtualHub.name, "hub");
        addEdge(virtualWan.id, virtualHub.id);
      }
    }

    for (const virtualHub of subscription.orphaned_virtual_hubs || []) {
      addNode(virtualHub.id, "hub", virtualHub.name, "hub");
    }

    for (const routeServer of subscription.route_servers || []) {
      addNode(routeServer.id, "routeServer", routeServer.name, "routeServer");
    }

    for (const connection of subscription.virtual_hub_vnet_connections || []) {
      if (connection.virtual_hub_id && connection.remote_virtual_network_id) {
        connectedVnetIds.add(connection.remote_virtual_network_id);
        addEdge(connection.virtual_hub_id, connection.remote_virtual_network_id);
      }
    }

    for (const vnet of subscription.virtual_networks || []) {
      addNode(vnet.id, "vnet", vnet.name, "vnet");

      for (const subnet of vnet.subnets || []) {
        for (const device of subnet.connected_devices || []) {
          if (device.public_ip_id) {
            publicIpToVnet.set(device.public_ip_id, vnet.id);
          }
        }
      }

      for (const peering of vnet.peerings || []) {
        const remoteId = peering.remote_virtual_network_id || `${peering.id}:remote`;
        const remoteLabel = peering.remote_virtual_network_id
          ? peering.remote_virtual_network_id.split("/").filter(Boolean).pop()
          : "remote vnet";
        addNode(remoteId, "peering", remoteLabel, "peering");
        addEdge(vnet.id, remoteId);
      }
    }

    for (const publicIp of subscription.public_ip_addresses || []) {
      addNode(publicIp.id, "publicIp", publicIp.name || publicIp.ip_address || "public ip", "publicIp");
      addEdge(publicIpToVnet.get(publicIp.id), publicIp.id);
      addEdge(publicIp.id, "internet:surface");
    }
  }

  return {
    title: "Network Shape",
    nodes,
    edges,
  };
}

function buildDeviceExposureGraph(model) {
  const nodes = [];
  const edges = [];
  const seen = new Set();

  function addNode(id, lane, label, tone) {
    if (!id || seen.has(id)) {
      return;
    }
    seen.add(id);
    nodes.push({ id, lane, label, tone: tone || lane });
  }

  function addEdge(source, target) {
    if (!source || !target) {
      return;
    }
    edges.push({ source, target, id: `${source}:${target}` });
  }

  addNode("internet:surface", "internet", "Internet Surface", "surface");

  for (const subscription of model?.subscriptions || []) {
    for (const vnet of subscription.virtual_networks || []) {
      addNode(vnet.id, "vnet", vnet.name, "vnet");

      for (const subnet of vnet.subnets || []) {
        addNode(subnet.id, "subnet", subnet.name, "subnet");
        addEdge(vnet.id, subnet.id);

        for (const device of subnet.connected_devices || []) {
          const deviceId = device.id || device.network_interface_id || `${subnet.id}:${device.name}`;
          const isExposed = Boolean(device.public_ip_id || device.public_ip_address);
          addNode(deviceId, "device", device.name || device.type || "device", isExposed ? "deviceExposed" : "device");
          addEdge(subnet.id, deviceId);

          if (device.public_ip_id) {
            addNode(
              device.public_ip_id,
              "publicIp",
              device.public_ip_name || device.public_ip_address || "public ip",
              "publicIp",
            );
            addEdge(deviceId, device.public_ip_id);
            addEdge(device.public_ip_id, "internet:surface");
          } else if (device.public_ip_address) {
            const pseudoPublicIpId = `publicIp:${deviceId}`;
            addNode(
              pseudoPublicIpId,
              "publicIp",
              device.public_ip_address,
              "publicIp",
            );
            addEdge(deviceId, pseudoPublicIpId);
            addEdge(pseudoPublicIpId, "internet:surface");
          }
        }
      }

      for (const peering of vnet.peerings || []) {
        const remoteId = peering.remote_virtual_network_id || `${peering.id}:remote`;
        const remoteLabel = peering.remote_virtual_network_id
          ? peering.remote_virtual_network_id.split("/").filter(Boolean).pop()
          : "remote vnet";
        addNode(remoteId, "peering", remoteLabel, "peering");
        addEdge(vnet.id, remoteId);
      }
    }
  }

  return {
    title: "Connected Devices",
    nodes,
    edges,
  };
}

export function findNetworkContext(model, selectedItem) {
  if (!model || !selectedItem) {
    return {};
  }

  for (const subscription of model.subscriptions || []) {
    if (selectedItem.kind === "subscription" && subscription.id === selectedItem.data.id) {
      return { subscription };
    }

    for (const publicIp of subscription.public_ip_addresses || []) {
      if (selectedItem.kind === "publicIp" && publicIp.id === selectedItem.data.id) {
        return { subscription, publicIp };
      }
    }

    for (const vnet of subscription.virtual_networks || []) {
      if (selectedItem.kind === "vnet" && vnet.id === selectedItem.data.id) {
        return { subscription, vnet };
      }

      for (const subnet of vnet.subnets || []) {
        if (selectedItem.kind === "subnet" && subnet.id === selectedItem.data.id) {
          return { subscription, vnet, subnet };
        }

        for (const device of subnet.connected_devices || []) {
          const deviceId = device.id || device.network_interface_id || device.name;
          if (selectedItem.kind === "device" && deviceId === (selectedItem.data.id || selectedItem.data.network_interface_id || selectedItem.data.name)) {
            return { subscription, vnet, subnet, device };
          }
        }
      }

      for (const peering of vnet.peerings || []) {
        if (selectedItem.kind === "peering" && peering.id === selectedItem.data.id) {
          return { subscription, vnet, peering };
        }
      }
    }
  }

  return {};
}

export function buildScopedNetworkGraph(model, selectedItem, view = "shape") {
  if (view === "shape") {
    return buildShapeGraph(model);
  }

  if (view === "devices") {
    return buildDeviceExposureGraph(model);
  }

  if (view === "topology") {
    return buildTopologyGraph(model);
  }

  if (selectedItem?.kind === "general") {
    const nodes = [];
    const edges = [];
    const seen = new Set();

    function addNode(id, lane, label, tone) {
      if (!id || seen.has(id)) {
        return;
      }
      seen.add(id);
      nodes.push({ id, lane, label, tone: tone || lane });
    }

    function addEdge(source, target) {
      if (!source || !target) {
        return;
      }
      edges.push({ source, target, id: `${source}:${target}` });
    }

    for (const subscription of model?.subscriptions || []) {
      addNode(subscription.id, "subscription", subscription.name, "subscription");

      for (const currentPublicIp of subscription.public_ip_addresses || []) {
        addNode(currentPublicIp.id, "publicIp", currentPublicIp.name || currentPublicIp.ip_address || "public ip", "publicIp");
        addEdge(subscription.id, currentPublicIp.id);
      }

      for (const vnet of subscription.virtual_networks || []) {
        addNode(vnet.id, "vnet", vnet.name, "vnet");
        addEdge(subscription.id, vnet.id);

        for (const subnet of vnet.subnets || []) {
          addNode(subnet.id, "subnet", subnet.name, "subnet");
          addEdge(vnet.id, subnet.id);

          for (const device of subnet.connected_devices || []) {
            const deviceId = device.id || device.network_interface_id || `${subnet.id}:${device.name}`;
            addNode(deviceId, "device", device.name || device.type || "device", "device");
            addEdge(subnet.id, deviceId);
            if (device.public_ip_id) {
              addNode(
                device.public_ip_id,
                "publicIp",
                device.public_ip_name || device.public_ip_address || "public ip",
                "publicIp",
              );
              addEdge(deviceId, device.public_ip_id);
            }
          }
        }

        for (const peering of vnet.peerings || []) {
          const remoteId = peering.remote_virtual_network_id || `${peering.id}:remote`;
          const remoteLabel = peering.remote_virtual_network_id
            ? peering.remote_virtual_network_id.split("/").filter(Boolean).pop()
            : "remote vnet";
          addNode(remoteId, "remote", remoteLabel, "peering");
          addEdge(vnet.id, remoteId);
        }
      }
    }

    return {
      title: "Topology",
      nodes,
      edges,
    };
  }

  const context = findNetworkContext(model, selectedItem);
  const nodes = [];
  const edges = [];
  const seen = new Set();

  function addNode(id, lane, label, tone) {
    if (!id || seen.has(id)) {
      return;
    }
    seen.add(id);
    nodes.push({ id, lane, label, tone: tone || lane });
  }

  function addEdge(source, target) {
    if (!source || !target) {
      return;
    }
    edges.push({ source, target, id: `${source}:${target}` });
  }

  const { subscription, vnet, subnet, device, peering, publicIp } = context;
  if (!subscription) {
    return { title: "Topology", nodes: [], edges: [] };
  }

  addNode(subscription.id, "subscription", subscription.name, "subscription");
  for (const currentPublicIp of subscription.public_ip_addresses || []) {
    if (publicIp && currentPublicIp.id !== publicIp.id) {
      continue;
    }
    addNode(currentPublicIp.id, "publicIp", currentPublicIp.name || currentPublicIp.ip_address || "public ip", "publicIp");
    addEdge(subscription.id, currentPublicIp.id);
  }

  const vnets = vnet ? [vnet] : subscription.virtual_networks || [];
  for (const currentVnet of vnets) {
    addNode(currentVnet.id, "vnet", currentVnet.name, "vnet");
    addEdge(subscription.id, currentVnet.id);

    const subnets = subnet ? [subnet] : currentVnet.subnets || [];
    for (const currentSubnet of subnets) {
      addNode(currentSubnet.id, "subnet", currentSubnet.name, "subnet");
      addEdge(currentVnet.id, currentSubnet.id);

      const devices = device ? [device] : currentSubnet.connected_devices || [];
      for (const currentDevice of devices) {
        const deviceId = currentDevice.id || currentDevice.network_interface_id || `${currentSubnet.id}:${currentDevice.name}`;
        addNode(deviceId, "device", currentDevice.name || currentDevice.type || "device", "device");
        addEdge(currentSubnet.id, deviceId);
        if (currentDevice.public_ip_id) {
          addNode(
            currentDevice.public_ip_id,
            "publicIp",
            currentDevice.public_ip_name || currentDevice.public_ip_address || "public ip",
            "publicIp",
          );
          addEdge(deviceId, currentDevice.public_ip_id);
        }
      }
    }

    for (const currentPeering of currentVnet.peerings || []) {
      if (peering && currentPeering.id !== peering.id) {
        continue;
      }
      const remoteId = currentPeering.remote_virtual_network_id || `${currentPeering.id}:remote`;
      const remoteLabel = currentPeering.remote_virtual_network_id
        ? currentPeering.remote_virtual_network_id.split("/").filter(Boolean).pop()
        : "remote vnet";
      addNode(remoteId, "remote", remoteLabel, "peering");
      addEdge(currentVnet.id, remoteId);
    }
  }

  return {
    title: vnet ? `${subscription.name} / ${vnet.name}` : subscription.name,
    nodes,
    edges,
  };
}

export function findNetworkInventoryKey(items, nodeId) {
  const matching = items.find((item) => {
    if (item.data?.id === nodeId) {
      return true;
    }
    if (item.kind === "device") {
      const deviceId = item.data?.id || item.data?.network_interface_id || item.data?.name;
      return deviceId === nodeId;
    }
    return false;
  });
  return matching?.key || "";
}
