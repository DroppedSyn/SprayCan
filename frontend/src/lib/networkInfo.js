// Facts shown in the graph's info popover. describeNetworkNode() resolves a graph node id
// (from any graph view) back to the network model and returns { kind, title, rows }, where
// rows are [label, value] pairs with empty values left out.

const ANY_SOURCES = new Set(["*", "any", "internet", "0.0.0.0/0", "::/0"]);

function nameFromId(id) {
  return String(id || "").split("/").filter(Boolean).pop() || "";
}

function subscriptionIdFromResourceId(id) {
  const match = String(id || "").match(/\/subscriptions\/([^/]+)/i);
  return match ? match[1] : "";
}

function yesNo(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "";
}

function list(values) {
  return (values || []).filter((value) => value !== null && value !== undefined && value !== "").join(", ");
}

function rows(pairs) {
  return pairs.filter(([, value]) => value !== null && value !== undefined && value !== "");
}

function ruleSources(rule) {
  return [rule.source_address_prefix, ...(rule.source_address_prefixes || [])].filter(Boolean);
}

function buildIndex(model) {
  const index = {
    vnets: new Map(), subnets: new Map(), devices: new Map(), nsgs: new Map(), publicIps: new Map(),
    routeTables: new Map(), natGateways: new Map(), hubs: new Map(), vwans: new Map(),
    nsgSubnets: new Map(), nsgNics: new Map(), peeringsByRemote: new Map(), publicIpOwner: new Map(),
  };
  for (const subscription of model?.subscriptions || []) {
    const sub = { id: subscription.id, name: subscription.name };
    for (const nsg of subscription.network_security_groups || []) index.nsgs.set(nsg.id, { nsg, sub });
    for (const ip of subscription.public_ip_addresses || []) index.publicIps.set(ip.id, { ip, sub });
    for (const table of subscription.route_tables || []) index.routeTables.set(table.id, table);
    for (const gateway of subscription.nat_gateways || []) index.natGateways.set(gateway.id, gateway);
    for (const hub of [...(subscription.orphaned_virtual_hubs || []), ...(subscription.route_servers || [])]) {
      index.hubs.set(hub.id, { hub, sub });
    }
    for (const vwan of subscription.virtual_wans || []) {
      index.vwans.set(vwan.id, { vwan, sub });
      for (const hub of vwan.virtual_hubs || []) index.hubs.set(hub.id, { hub, sub, vwan });
    }
    for (const vnet of subscription.virtual_networks || []) {
      index.vnets.set(vnet.id, { vnet, sub });
      for (const peering of vnet.peerings || []) {
        const key = peering.remote_virtual_network_id || `${peering.id}:remote`;
        if (!index.peeringsByRemote.has(key)) index.peeringsByRemote.set(key, []);
        index.peeringsByRemote.get(key).push({ peering, vnet });
      }
      for (const subnet of vnet.subnets || []) {
        index.subnets.set(subnet.id, { subnet, vnet, sub });
        if (subnet.network_security_group_id) {
          if (!index.nsgSubnets.has(subnet.network_security_group_id)) index.nsgSubnets.set(subnet.network_security_group_id, []);
          index.nsgSubnets.get(subnet.network_security_group_id).push(subnet.name);
        }
        for (const device of subnet.connected_devices || []) {
          const deviceId = device.id || device.network_interface_id || `${subnet.id}:${device.name}`;
          if (!index.devices.has(deviceId)) index.devices.set(deviceId, { device, subnet, vnet, sub });
          if (device.network_security_group_id) {
            if (!index.nsgNics.has(device.network_security_group_id)) index.nsgNics.set(device.network_security_group_id, []);
            index.nsgNics.get(device.network_security_group_id).push(device.network_interface_name || device.name);
          }
          if (device.public_ip_id) index.publicIpOwner.set(device.public_ip_id, device);
        }
      }
    }
  }
  return index;
}

const indexCache = new WeakMap();

function getIndex(model) {
  if (!model) return null;
  if (!indexCache.has(model)) indexCache.set(model, buildIndex(model));
  return indexCache.get(model);
}

function describeVnet({ vnet, sub }, index) {
  const subnets = vnet.subnets || [];
  const peerings = vnet.peerings || [];
  return {
    kind: "Virtual network",
    title: vnet.name,
    rows: rows([
      ["Address space", list(vnet.address_spaces) || "Not recorded"],
      ["Region", vnet.region],
      ["Subscription", sub.name],
      ["Subnets", `${subnets.length} (${subnets.filter((subnet) => subnet.network_security_group_id).length} with an NSG)`],
      ["Connected devices", String(subnets.reduce((total, subnet) => total + (subnet.connected_devices || []).length, 0))],
      ["Peerings", peerings.length
        ? peerings.map((peering) => `${nameFromId(peering.remote_virtual_network_id) || peering.name} (${peering.state || "unknown"})`).join(", ")
        : "None"],
      ["DNS servers", list(vnet.dns_servers) || "Azure-provided"],
      ["DDoS protection", vnet.enable_ddos_protection === true ? "Enabled" : vnet.enable_ddos_protection === false ? "Disabled" : ""],
      ["Resource ID", vnet.id],
    ]),
  };
}

function describeSubnet({ subnet, vnet, sub }, index) {
  const nsg = index.nsgs.get(subnet.network_security_group_id)?.nsg;
  return {
    kind: "Subnet",
    title: subnet.name,
    rows: rows([
      ["Address prefix", subnet.address_prefix || list(subnet.address_prefixes) || "Not recorded"],
      ["Virtual network", vnet.name],
      ["Subscription", sub.name],
      ["NSG", subnet.network_security_group_id ? nsg?.name || nameFromId(subnet.network_security_group_id) : "None"],
      ["Route table", subnet.route_table_id ? index.routeTables.get(subnet.route_table_id)?.name || nameFromId(subnet.route_table_id) : "None"],
      ["NAT gateway", subnet.nat_gateway_id ? index.natGateways.get(subnet.nat_gateway_id)?.name || nameFromId(subnet.nat_gateway_id) : "None"],
      ["Connected devices", String((subnet.connected_devices || []).length)],
      ["Service endpoints", list((subnet.service_endpoints || []).map((endpoint) => endpoint.service))],
      ["Delegations", list(subnet.delegations)],
      ["Private endpoint policies", subnet.private_endpoint_policies],
      ["Resource ID", subnet.id],
    ]),
  };
}

function describeNsg({ nsg, sub }, index) {
  const rules = nsg.security_rules || [];
  const inboundAllow = rules.filter(
    (rule) => String(rule.direction).toLowerCase() === "inbound" && String(rule.access).toLowerCase() === "allow",
  );
  const fromAny = inboundAllow.filter((rule) => ruleSources(rule).some((source) => ANY_SOURCES.has(String(source).toLowerCase())));
  const subnets = index.nsgSubnets.get(nsg.id) || [];
  const nics = index.nsgNics.get(nsg.id) || [];
  return {
    kind: "Network security group",
    title: nsg.name,
    rows: rows([
      ["Region", nsg.region],
      ["Subscription", sub.name],
      ["Custom rules", `${rules.length} (${rules.filter((rule) => String(rule.direction).toLowerCase() === "inbound").length} inbound)`],
      ["Inbound allow rules", String(inboundAllow.length)],
      ["Inbound allow from any source", fromAny.length ? `${fromAny.length}: ${fromAny.map((rule) => rule.name).join(", ")}` : "0"],
      ["Attached subnets", subnets.length ? list(subnets) : "None"],
      ["Attached NICs", nics.length ? list(nics) : "None"],
      ["Resource ID", nsg.id],
    ]),
  };
}

function describeDevice({ device, subnet, vnet }, index) {
  return {
    kind: device.type ? `Device · ${device.type}` : "Device",
    title: device.name || device.network_interface_name || "Device",
    rows: rows([
      ["Private IP", device.private_ip ? `${device.private_ip}${device.private_ip_allocation ? ` (${device.private_ip_allocation})` : ""}` : ""],
      ["Public IP", device.public_ip_address || (device.public_ip_id ? nameFromId(device.public_ip_id) : "None")],
      ["Subnet", `${subnet.name} (${vnet.name})`],
      ["Network interface", device.network_interface_name],
      ["NIC NSG", device.network_security_group_id ? index.nsgs.get(device.network_security_group_id)?.nsg.name || nameFromId(device.network_security_group_id) : "None"],
      ["IP forwarding", yesNo(device.enable_ip_forwarding)],
      ["Application security groups", list((device.application_security_group_ids || []).map(nameFromId))],
      ["Resource ID", device.id],
    ]),
  };
}

function describePublicIp({ ip, sub }, index) {
  const owner = index.publicIpOwner.get(ip.id);
  return {
    kind: "Public IP address",
    title: ip.name,
    rows: rows([
      ["Address", ip.ip_address || "Not allocated"],
      ["DNS name", ip.fqdn],
      ["Attached to", owner ? owner.name || owner.network_interface_name : ""],
      ["SKU", ip.sku],
      ["Allocation", ip.allocation_method],
      ["IP version", ip.ip_version],
      ["DDoS protection", ip.ddos_protection_mode],
      ["Subscription", sub.name],
      ["Resource ID", ip.id],
    ]),
  };
}

function describeHub({ hub, sub, vwan }) {
  const gateways = [
    ["VPN", hub.vpn_gateway_id], ["P2S VPN", hub.p2s_vpn_gateway_id],
    ["ExpressRoute", hub.express_route_gateway_id], ["Firewall", hub.azure_firewall_id],
  ].filter(([, id]) => id).map(([label, id]) => `${label}: ${nameFromId(id)}`);
  const isRouteServer = String(hub.kind || "").toLowerCase() === "routeserver";
  return {
    kind: isRouteServer ? "Route Server" : "Virtual hub",
    title: hub.name,
    rows: rows([
      ["Address prefix", hub.address_prefix],
      ["Region", hub.region],
      ["Virtual WAN", vwan?.name || (hub.virtual_wan_id ? nameFromId(hub.virtual_wan_id) : "")],
      ["SKU", hub.sku],
      ["Router ASN", hub.router_asn != null ? String(hub.router_asn) : ""],
      ["Router IPs", list(hub.router_ips)],
      ["Branch-to-branch traffic", yesNo(hub.allow_branch_to_branch_traffic)],
      ["Gateways", list(gateways)],
      ["Security provider", hub.security_provider_name],
      ["Subscription", sub.name],
      ["Resource ID", hub.id],
    ]),
  };
}

function describeVwan({ vwan, sub }) {
  return {
    kind: "Virtual WAN",
    title: vwan.name,
    rows: rows([
      ["Type", vwan.type],
      ["Region", vwan.region],
      ["Hubs", String((vwan.virtual_hubs || []).length)],
      ["Branch-to-branch traffic", yesNo(vwan.allow_branch_to_branch_traffic)],
      ["VNet-to-VNet traffic", yesNo(vwan.allow_vnet_to_vnet_traffic)],
      ["VPN encryption disabled", yesNo(vwan.disable_vpn_encryption)],
      ["Subscription", sub.name],
      ["Resource ID", vwan.id],
    ]),
  };
}

function describeRemotePeering(remoteId, peerings) {
  return {
    kind: "Peered VNet (outside this model)",
    title: nameFromId(remoteId) || "Remote virtual network",
    rows: rows([
      ["Peered from", peerings.map(({ peering, vnet }) => `${vnet.name} (${peering.state || "unknown"})`).join(", ")],
      ["Forwarded traffic allowed", list([...new Set(peerings.map(({ peering }) => yesNo(peering.allow_forwarded_traffic)))])],
      ["Gateway transit", list([...new Set(peerings.map(({ peering }) => yesNo(peering.allow_gateway_transit || peering.use_remote_gateways)))])],
      ["Remote subscription", subscriptionIdFromResourceId(remoteId)],
      ["Resource ID", remoteId.includes("/") ? remoteId : ""],
    ]),
  };
}

function describeInternet(index) {
  const exposed = [...index.devices.values()].filter(({ device }) => device.public_ip_id || device.public_ip_address);
  return {
    kind: "Internet",
    title: "Internet surface",
    rows: rows([
      ["Public IP addresses", String(index.publicIps.size)],
      ["Devices with a public IP", String(exposed.length)],
    ]),
  };
}

export function describeNetworkNode(model, nodeId, ref) {
  const index = getIndex(model);
  if (!index || !nodeId) return null;
  const id = ref || nodeId;

  if (id === "internet:surface") return describeInternet(index);
  if (index.vnets.has(id)) return describeVnet(index.vnets.get(id), index);
  if (index.subnets.has(id)) return describeSubnet(index.subnets.get(id), index);
  if (index.nsgs.has(id)) return describeNsg(index.nsgs.get(id), index);
  if (index.devices.has(id)) return describeDevice(index.devices.get(id), index);
  if (index.publicIps.has(id)) return describePublicIp(index.publicIps.get(id), index);
  if (index.hubs.has(id)) return describeHub(index.hubs.get(id));
  if (index.vwans.has(id)) return describeVwan(index.vwans.get(id));
  if (id.startsWith("publicIp:") && index.devices.has(id.slice("publicIp:".length))) {
    const { device } = index.devices.get(id.slice("publicIp:".length));
    return {
      kind: "Public IP address",
      title: device.public_ip_name || device.public_ip_address || "Public IP",
      rows: rows([["Address", device.public_ip_address], ["Attached to", device.name], ["Resource ID", device.public_ip_id]]),
    };
  }
  if (index.peeringsByRemote.has(id)) return describeRemotePeering(id, index.peeringsByRemote.get(id));

  return { kind: "Element", title: nameFromId(id) || id, rows: rows([["ID", id]]) };
}
