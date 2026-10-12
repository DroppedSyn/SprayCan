import json
from datetime import datetime, timezone

import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, write_json_payload_to_disk


class Droplet:
    droplet_name = "Util: Model Azure Network"
    droplet_path = None
    droplet_type = "util"
    droplet_description = (
        "Builds a JSON snapshot of the Azure network topology across all\n"
        "subscriptions: VNets, subnets, peerings, NSGs, route tables, and\n"
        "network interfaces. Useful as an offline reference for network\n"
        "architecture review.\n"
        "\n"
        "Requires\n"
        "  ARM : Reader on subscriptions"
    )

    network_api_version = "2023-09-01"
    subscriptions_api_version = "2022-12-01"

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def arm_get(self, url):
        full_url = "https://management.azure.com%s" % url
        headers = {
            "Authorization": "Bearer %s" % tokenizer.get_arm_token(),
            "Content-Type": "application/json",
        }
        return http_client.get(url=full_url, headers=headers)

    def get_all_subscriptions(self):
        return self.arm_get("/subscriptions?api-version=%s" % self.subscriptions_api_version)

    def get_all_virtual_networks(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/virtualNetworks?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_network_interfaces(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/networkInterfaces?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_private_endpoints(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/privateEndpoints?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_public_ip_addresses(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/publicIPAddresses?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_virtual_wans(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/virtualWans?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_virtual_hubs(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/virtualHubs?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_network_security_groups(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_route_tables(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/routeTables?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_nat_gateways(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/natGateways?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_load_balancers(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/loadBalancers?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_application_gateways(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/applicationGateways?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_virtual_network_gateways(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/virtualNetworkGateways?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_all_local_network_gateways(self, subscription_id):
        return self.arm_get(
            "/subscriptions/%s/providers/Microsoft.Network/localNetworkGateways?api-version=%s"
            % (subscription_id, self.network_api_version)
        )

    def get_hub_vnet_connections(self, subscription_id, resource_group, hub_name):
        # Unlike every other resource type here, hubVirtualNetworkConnections has no
        # subscription-wide "list all" endpoint — ARM only exposes it scoped to a specific
        # resource group + virtualHub (.../virtualHubs/{hubName}/hubVirtualNetworkConnections).
        # A flat /subscriptions/{id}/providers/Microsoft.Network/hubVirtualNetworkConnections
        # call 404s with InvalidResourceType; it's not a valid subscription-level route.
        return self.arm_get(
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualHubs/%s"
            "/hubVirtualNetworkConnections?api-version=%s"
            % (subscription_id, resource_group, hub_name, self.network_api_version)
        )

    def parse_resource_group_from_id(self, resource_id):
        parts = (resource_id or "").split("/")
        for index, part in enumerate(parts):
            if part.lower() == "resourcegroups" and index + 1 < len(parts):
                return parts[index + 1]
        return None

    def collect_values(self, response, label=None):
        try:
            json_res = json.loads(response.content or "{}")
        except ValueError:
            json_res = {}

        if response.status_code != 200:
            # Without this check, a 403 (missing Reader role) or any other ARM error looks
            # identical to "this subscription genuinely has none of this resource type" —
            # silently producing an incomplete security review with no indication anything
            # was missed.
            error = json_res.get("error") or {}
            error_code = error.get("code") or ""
            error_message = error.get("message") or "Unknown ARM error"
            console.warn(
                "[!] ARM request failed with HTTP %s%s: %s%s"
                % (
                    response.status_code,
                    " for %s" % label if label else "",
                    error_message,
                    " (%s)" % error_code if error_code else "",
                )
            )
            return []

        if "value" in json_res:
            return check_pagination(tokenizer.get_arm_token(), json_res, json_res["value"])
        return []

    def collect_named_values(self, label, response):
        values = self.collect_values(response, label=label)
        console.debug("[↳] %s: %s" % (label, len(values)))
        return values

    def build_peering(self, peering):
        props = peering.get("properties", {})
        remote_vnet = (props.get("remoteVirtualNetwork") or {}).get("id")
        return {
            "id": peering.get("id"),
            "name": peering.get("name"),
            "remote_virtual_network_id": remote_vnet,
            "state": props.get("peeringState"),
            "allow_virtual_network_access": props.get("allowVirtualNetworkAccess"),
            "allow_forwarded_traffic": props.get("allowForwardedTraffic"),
            "allow_gateway_transit": props.get("allowGatewayTransit"),
            "use_remote_gateways": props.get("useRemoteGateways"),
        }

    def build_connected_device_from_nic(self, nic, ip_config, public_ip_lookup):
        nic_props = nic.get("properties", {})
        ip_props = ip_config.get("properties", {})
        vm = nic_props.get("virtualMachine") or {}
        network_security_group = nic_props.get("networkSecurityGroup") or {}
        attachment_id = vm.get("id") or nic.get("id")
        attachment_name = attachment_id.split("/")[-1] if attachment_id else nic.get("name")
        attachment_type = "virtualMachine" if vm.get("id") else "networkInterface"
        public_ip_id = ((ip_props.get("publicIPAddress") or {}).get("id"))
        public_ip = public_ip_lookup.get(public_ip_id, {})

        return {
            "type": attachment_type,
            "id": attachment_id,
            "name": attachment_name,
            "network_interface_id": nic.get("id"),
            "network_interface_name": nic.get("name"),
            "network_security_group_id": network_security_group.get("id"),
            # IP forwarding lets the NIC route traffic not addressed to itself — a classic
            # NVA/lateral-movement/spoofing indicator worth surfacing in a security review.
            "enable_ip_forwarding": nic_props.get("enableIPForwarding"),
            "application_security_group_ids": [
                asg.get("id") for asg in ip_props.get("applicationSecurityGroups", []) if asg.get("id")
            ],
            "private_ip": ip_props.get("privateIPAddress"),
            "private_ip_allocation": ip_props.get("privateIPAllocationMethod"),
            "public_ip_id": public_ip_id,
            "public_ip_address": public_ip.get("ip_address"),
            "public_ip_name": public_ip.get("name"),
        }

    def build_public_ip(self, public_ip):
        props = public_ip.get("properties", {})
        dns_settings = props.get("dnsSettings") or {}
        ddos_settings = props.get("ddosSettings") or {}
        return {
            "id": public_ip.get("id"),
            "name": public_ip.get("name"),
            "ip_address": props.get("ipAddress"),
            "ip_version": props.get("publicIPAddressVersion"),
            "allocation_method": props.get("publicIPAllocationMethod"),
            "sku": ((public_ip.get("sku") or {}).get("name")),
            "fqdn": dns_settings.get("fqdn"),
            "ip_tags": props.get("ipTags", []),
            "ddos_protection_mode": ddos_settings.get("protectionMode"),
            "ddos_protection_plan_id": (ddos_settings.get("ddosProtectionPlan") or {}).get("id"),
        }

    def build_virtual_hub(self, hub):
        props = hub.get("properties", {})
        return {
            "id": hub.get("id"),
            "name": hub.get("name"),
            "region": hub.get("location"),
            "kind": hub.get("kind"),
            "address_prefix": props.get("addressPrefix"),
            "sku": props.get("sku"),
            "routing_preference": props.get("hubRoutingPreference"),
            "preferred_routing_gateway": props.get("preferredRoutingGateway"),
            "router_asn": props.get("virtualRouterAsn"),
            "router_ips": props.get("virtualRouterIps", []),
            "allow_branch_to_branch_traffic": props.get("allowBranchToBranchTraffic"),
            "virtual_wan_id": (props.get("virtualWan") or {}).get("id"),
            "vpn_gateway_id": (props.get("vpnGateway") or {}).get("id"),
            "p2s_vpn_gateway_id": (props.get("p2SVpnGateway") or {}).get("id"),
            "express_route_gateway_id": (props.get("expressRouteGateway") or {}).get("id"),
            "azure_firewall_id": (props.get("azureFirewall") or {}).get("id"),
            "security_provider_name": props.get("securityProviderName"),
            "security_partner_provider_id": (props.get("securityPartnerProvider") or {}).get("id"),
            "route_table_id": (props.get("routeTable") or {}).get("id"),
            "route_table_v2_ids": [
                route_table.get("id")
                for route_table in props.get("virtualHubRouteTableV2s", [])
                if route_table.get("id")
            ],
        }

    def build_virtual_wan(self, virtual_wan, attached_hubs):
        props = virtual_wan.get("properties", {})
        return {
            "id": virtual_wan.get("id"),
            "name": virtual_wan.get("name"),
            "region": virtual_wan.get("location"),
            "type": props.get("type"),
            "disable_vpn_encryption": props.get("disableVpnEncryption"),
            "allow_branch_to_branch_traffic": props.get("allowBranchToBranchTraffic"),
            "allow_vnet_to_vnet_traffic": props.get("allowVnetToVnetTraffic"),
            "office365_local_breakout_category": props.get("office365LocalBreakoutCategory"),
            "virtual_hubs": attached_hubs,
        }

    def build_security_rule(self, rule):
        rule_props = rule.get("properties", {})
        return {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "priority": rule_props.get("priority"),
            "direction": rule_props.get("direction"),
            "access": rule_props.get("access"),
            "protocol": rule_props.get("protocol"),
            "source_port_range": rule_props.get("sourcePortRange"),
            "source_port_ranges": rule_props.get("sourcePortRanges", []),
            "destination_port_range": rule_props.get("destinationPortRange"),
            "destination_port_ranges": rule_props.get("destinationPortRanges", []),
            "source_address_prefix": rule_props.get("sourceAddressPrefix"),
            "source_address_prefixes": rule_props.get("sourceAddressPrefixes", []),
            "destination_address_prefix": rule_props.get("destinationAddressPrefix"),
            "destination_address_prefixes": rule_props.get("destinationAddressPrefixes", []),
            "source_application_security_group_ids": [
                asg.get("id") for asg in rule_props.get("sourceApplicationSecurityGroups", []) if asg.get("id")
            ],
            "destination_application_security_group_ids": [
                asg.get("id") for asg in rule_props.get("destinationApplicationSecurityGroups", []) if asg.get("id")
            ],
        }

    def build_network_security_group(self, nsg):
        props = nsg.get("properties", {})
        return {
            "id": nsg.get("id"),
            "name": nsg.get("name"),
            "region": nsg.get("location"),
            "security_rules": [self.build_security_rule(rule) for rule in props.get("securityRules", [])],
            # Azure's implicit baseline rules (AllowVnetInBound, DenyAllInBound, etc.) —
            # without these, "what happens to traffic no custom rule matches?" is invisible,
            # which is exactly the question that decides whether a subnet is reachable.
            "default_security_rules": [
                self.build_security_rule(rule) for rule in props.get("defaultSecurityRules", [])
            ],
        }

    def build_route_table(self, route_table):
        props = route_table.get("properties", {})
        routes = []
        for route in props.get("routes", []):
            route_props = route.get("properties", {})
            routes.append({
                "id": route.get("id"),
                "name": route.get("name"),
                "address_prefix": route_props.get("addressPrefix"),
                "next_hop_type": route_props.get("nextHopType"),
                "next_hop_ip_address": route_props.get("nextHopIpAddress"),
            })
        return {
            "id": route_table.get("id"),
            "name": route_table.get("name"),
            "region": route_table.get("location"),
            "disable_bgp_route_propagation": props.get("disableBgpRoutePropagation"),
            "routes": routes,
        }

    def build_nat_gateway(self, nat_gateway):
        props = nat_gateway.get("properties", {})
        return {
            "id": nat_gateway.get("id"),
            "name": nat_gateway.get("name"),
            "region": nat_gateway.get("location"),
            "sku": (nat_gateway.get("sku") or {}).get("name"),
            "idle_timeout_minutes": props.get("idleTimeoutInMinutes"),
            "public_ip_address_ids": [
                item.get("id") for item in props.get("publicIpAddresses", []) if item.get("id")
            ],
            "public_ip_prefix_ids": [
                item.get("id") for item in props.get("publicIpPrefixes", []) if item.get("id")
            ],
            "subnet_ids": [
                item.get("id") for item in props.get("subnets", []) if item.get("id")
            ],
        }

    def build_frontend_ip_configuration(self, config):
        props = config.get("properties", {})
        return {
            "id": config.get("id"),
            "name": config.get("name"),
            "private_ip_address": props.get("privateIPAddress"),
            "private_ip_allocation_method": props.get("privateIPAllocationMethod"),
            "subnet_id": (props.get("subnet") or {}).get("id"),
            "public_ip_address_id": (props.get("publicIPAddress") or {}).get("id"),
        }

    def build_load_balancing_rule(self, rule):
        rule_props = rule.get("properties", {})
        # backendAddressPools (plural) is the current field; backendAddressPool (singular)
        # is the older single-pool reference some API versions/rules still populate.
        backend_pools = rule_props.get("backendAddressPools") or (
            [rule_props["backendAddressPool"]] if rule_props.get("backendAddressPool") else []
        )
        return {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "protocol": rule_props.get("protocol"),
            "frontend_port": rule_props.get("frontendPort"),
            "backend_port": rule_props.get("backendPort"),
            "frontend_ip_configuration_id": (rule_props.get("frontendIPConfiguration") or {}).get("id"),
            "backend_address_pool_ids": [pool.get("id") for pool in backend_pools if pool.get("id")],
        }

    def build_inbound_nat_rule(self, rule):
        rule_props = rule.get("properties", {})
        return {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "protocol": rule_props.get("protocol"),
            "frontend_port": rule_props.get("frontendPort"),
            "backend_port": rule_props.get("backendPort"),
            "frontend_ip_configuration_id": (rule_props.get("frontendIPConfiguration") or {}).get("id"),
        }

    def build_load_balancer(self, load_balancer):
        props = load_balancer.get("properties", {})
        sku = load_balancer.get("sku") or {}
        return {
            "id": load_balancer.get("id"),
            "name": load_balancer.get("name"),
            "region": load_balancer.get("location"),
            "sku": sku.get("name"),
            "sku_tier": sku.get("tier"),
            "frontend_ip_configurations": [
                self.build_frontend_ip_configuration(config)
                for config in props.get("frontendIPConfigurations", [])
            ],
            "backend_pool_ids": [
                pool.get("id") for pool in props.get("backendAddressPools", []) if pool.get("id")
            ],
            # What ports/protocol are actually forwarded from a frontend to backends —
            # frontend/backend pool IDs alone don't reveal exposure (e.g. RDP/3389, SQL/1433).
            "load_balancing_rules": [
                self.build_load_balancing_rule(rule) for rule in props.get("loadBalancingRules", [])
            ],
            "inbound_nat_rules": [
                self.build_inbound_nat_rule(rule) for rule in props.get("inboundNatRules", [])
            ],
        }

    def build_http_listener(self, listener):
        listener_props = listener.get("properties", {})
        return {
            "id": listener.get("id"),
            "name": listener.get("name"),
            "protocol": listener_props.get("protocol"),
            "host_name": listener_props.get("hostName"),
            "host_names": listener_props.get("hostNames", []),
            "frontend_ip_configuration_id": (listener_props.get("frontendIPConfiguration") or {}).get("id"),
            "ssl_certificate_id": (listener_props.get("sslCertificate") or {}).get("id"),
        }

    def build_application_gateway(self, application_gateway):
        props = application_gateway.get("properties", {})
        # Legacy per-gateway WAF config (Standard_v2/WAF_v2 without a FirewallPolicy attached).
        waf_config = props.get("webApplicationFirewallConfiguration") or {}
        ssl_policy = props.get("sslPolicy") or {}
        return {
            "id": application_gateway.get("id"),
            "name": application_gateway.get("name"),
            "region": application_gateway.get("location"),
            "sku": ((props.get("sku") or {}).get("name")),
            "tier": ((props.get("sku") or {}).get("tier")),
            "enable_http2": props.get("enableHttp2"),
            "gateway_ip_configuration_subnet_ids": [
                ((config.get("properties") or {}).get("subnet") or {}).get("id")
                for config in props.get("gatewayIPConfigurations", [])
                if ((config.get("properties") or {}).get("subnet") or {}).get("id")
            ],
            "frontend_ip_configurations": [
                self.build_frontend_ip_configuration(config)
                for config in props.get("frontendIPConfigurations", [])
            ],
            "http_listeners": [
                self.build_http_listener(listener) for listener in props.get("httpListeners", [])
            ],
            "ssl_certificate_count": len(props.get("sslCertificates", [])),
            # TLS posture — minProtocolVersion/cipherSuites decide whether weak TLS is accepted.
            "ssl_policy_type": ssl_policy.get("policyType"),
            "ssl_policy_name": ssl_policy.get("policyName"),
            "ssl_min_protocol_version": ssl_policy.get("minProtocolVersion"),
            "ssl_cipher_suites": ssl_policy.get("cipherSuites", []),
            # WAF presence/mode — the modern path is a FirewallPolicy reference; the legacy
            # path is this inline block. A gateway with neither has no WAF at all.
            "firewall_policy_id": (props.get("firewallPolicy") or {}).get("id"),
            "waf_enabled": waf_config.get("enabled"),
            "waf_firewall_mode": waf_config.get("firewallMode"),
            "waf_rule_set_type": waf_config.get("ruleSetType"),
            "waf_rule_set_version": waf_config.get("ruleSetVersion"),
            "waf_disabled_rule_groups": [
                group.get("ruleGroupName")
                for group in waf_config.get("disabledRuleGroups", [])
                if group.get("ruleGroupName")
            ],
        }

    def build_virtual_network_gateway(self, gateway):
        props = gateway.get("properties", {})
        # Point-to-Site VPN client auth posture: certificate-only (weaker — no central
        # revocation/MFA) vs AAD-authenticated vs RADIUS. Absent entirely if P2S isn't configured.
        vpn_client_config = props.get("vpnClientConfiguration") or {}
        return {
            "id": gateway.get("id"),
            "name": gateway.get("name"),
            "region": gateway.get("location"),
            "gateway_type": props.get("gatewayType"),
            "vpn_type": props.get("vpnType"),
            "enable_bgp": props.get("enableBgp"),
            "active_active": props.get("activeActive"),
            "sku": ((props.get("sku") or {}).get("name")),
            "ip_configuration_subnet_ids": [
                ((config.get("properties") or {}).get("subnet") or {}).get("id")
                for config in props.get("ipConfigurations", [])
                if ((config.get("properties") or {}).get("subnet") or {}).get("id")
            ],
            "public_ip_address_ids": [
                ((config.get("properties") or {}).get("publicIPAddress") or {}).get("id")
                for config in props.get("ipConfigurations", [])
                if ((config.get("properties") or {}).get("publicIPAddress") or {}).get("id")
            ],
            "vpn_client_address_pools": (vpn_client_config.get("vpnClientAddressPool") or {}).get(
                "addressPrefixes", []
            ),
            "vpn_client_protocols": vpn_client_config.get("vpnClientProtocols", []),
            "vpn_client_authentication_types": vpn_client_config.get("vpnAuthenticationTypes", []),
            "vpn_client_aad_tenant": vpn_client_config.get("aadTenant"),
            "vpn_client_root_certificate_count": len(vpn_client_config.get("vpnClientRootCertificates", [])),
        }

    def build_local_network_gateway(self, gateway):
        props = gateway.get("properties", {})
        return {
            "id": gateway.get("id"),
            "name": gateway.get("name"),
            "region": gateway.get("location"),
            "gateway_ip_address": props.get("gatewayIpAddress"),
            "fqdn": props.get("fqdn"),
            "address_prefixes": (props.get("localNetworkAddressSpace") or {}).get("addressPrefixes", []),
        }

    def build_virtual_hub_vnet_connection(self, connection):
        props = connection.get("properties", {})
        routing = props.get("routingConfiguration") or {}
        return {
            "id": connection.get("id"),
            "name": connection.get("name"),
            "remote_virtual_network_id": (props.get("remoteVirtualNetwork") or {}).get("id"),
            "virtual_hub_id": (props.get("virtualHub") or {}).get("id"),
            "enable_internet_security": props.get("enableInternetSecurity"),
            "routing_associated_route_table_id": ((routing.get("associatedRouteTable") or {}).get("id")),
            "routing_propagated_route_table_ids": [
                item.get("id")
                for item in ((routing.get("propagatedRouteTables") or {}).get("ids") or [])
                if item.get("id")
            ],
            "routing_static_route_count": len(routing.get("staticRoutes", [])),
        }

    def build_private_link_service_connection(self, conn):
        conn_props = conn.get("properties", {})
        state = conn_props.get("privateLinkServiceConnectionState") or {}
        return {
            "name": conn.get("name"),
            # Approved/Pending/Rejected/Disconnected — a stale Rejected/Disconnected connection
            # is an orphaned artifact; a long-Pending one may be an unapproved cross-tenant attempt.
            "status": state.get("status"),
        }

    def build_connected_device_from_private_endpoint(self, private_endpoint):
        props = private_endpoint.get("properties", {})
        return {
            "type": "privateEndpoint",
            "id": private_endpoint.get("id"),
            "name": private_endpoint.get("name"),
            "network_interface_ids": [
                nic.get("id") for nic in props.get("networkInterfaces", []) if nic.get("id")
            ],
            "private_link_service_connections": [
                self.build_private_link_service_connection(conn)
                for conn in props.get("privateLinkServiceConnections", [])
                if conn.get("name")
            ],
            "manual_private_link_service_connections": [
                self.build_private_link_service_connection(conn)
                for conn in props.get("manualPrivateLinkServiceConnections", [])
                if conn.get("name")
            ],
        }

    def build_subnet(self, subnet, subnet_connections):
        props = subnet.get("properties", {})
        return {
            "id": subnet.get("id"),
            "name": subnet.get("name"),
            "address_prefix": props.get("addressPrefix"),
            "address_prefixes": props.get("addressPrefixes", []),
            "network_security_group_id": (props.get("networkSecurityGroup") or {}).get("id"),
            "route_table_id": (props.get("routeTable") or {}).get("id"),
            "nat_gateway_id": (props.get("natGateway") or {}).get("id"),
            "private_endpoint_policies": props.get("privateEndpointNetworkPolicies"),
            "private_link_service_policies": props.get("privateLinkServiceNetworkPolicies"),
            # Which Azure services are reachable without traversing the internet/NSG egress
            # rules (data-exfiltration relevant), and what the subnet is delegated to.
            "service_endpoints": [
                {"service": se.get("service"), "locations": se.get("locations", [])}
                for se in props.get("serviceEndpoints", [])
            ],
            "delegations": [
                (delegation.get("properties") or {}).get("serviceName")
                for delegation in props.get("delegations", [])
                if (delegation.get("properties") or {}).get("serviceName")
            ],
            "connected_devices": subnet_connections,
        }

    def collect_subscription_network_model(self, subscription):
        subscription_id = subscription.get("subscriptionId") or subscription.get("id")
        status.set_phase("Subscription: %s" % subscription.get("displayName"))

        virtual_networks = self.collect_named_values("virtual networks", self.get_all_virtual_networks(subscription_id))
        network_interfaces = self.collect_named_values("network interfaces", self.get_all_network_interfaces(subscription_id))
        private_endpoints = self.collect_named_values("private endpoints", self.get_all_private_endpoints(subscription_id))
        public_ip_addresses = self.collect_named_values("public IP addresses", self.get_all_public_ip_addresses(subscription_id))
        virtual_wans = self.collect_named_values("virtual WANs", self.get_all_virtual_wans(subscription_id))
        virtual_hubs = self.collect_named_values("virtual hubs", self.get_all_virtual_hubs(subscription_id))
        network_security_groups = self.collect_named_values("network security groups", self.get_all_network_security_groups(subscription_id))
        route_tables = self.collect_named_values("route tables", self.get_all_route_tables(subscription_id))
        nat_gateways = self.collect_named_values("NAT gateways", self.get_all_nat_gateways(subscription_id))
        load_balancers = self.collect_named_values("load balancers", self.get_all_load_balancers(subscription_id))
        application_gateways = self.collect_named_values("application gateways", self.get_all_application_gateways(subscription_id))
        virtual_network_gateways = self.collect_named_values("virtual network gateways", self.get_all_virtual_network_gateways(subscription_id))
        local_network_gateways = self.collect_named_values("local network gateways", self.get_all_local_network_gateways(subscription_id))

        virtual_hub_vnet_connections = []
        for hub in virtual_hubs:
            resource_group = self.parse_resource_group_from_id(hub.get("id"))
            hub_name = hub.get("name")
            if not resource_group or not hub_name:
                continue
            virtual_hub_vnet_connections += self.collect_named_values(
                "virtual hub vnet connections (%s)" % hub_name,
                self.get_hub_vnet_connections(subscription_id, resource_group, hub_name),
            )

        public_ip_lookup = {
            public_ip.get("id"): self.build_public_ip(public_ip)
            for public_ip in public_ip_addresses
            if public_ip.get("id")
        }
        hub_ids_with_vnet_connections = {
            ((connection.get("properties") or {}).get("virtualHub") or {}).get("id")
            for connection in virtual_hub_vnet_connections
        }
        hub_ids_with_vnet_connections.discard(None)

        virtual_hubs_by_wan = {}
        orphaned_virtual_hubs = []
        route_servers = []

        for virtual_hub in virtual_hubs:
            modeled_hub = self.build_virtual_hub(virtual_hub)
            virtual_wan_id = modeled_hub.get("virtual_wan_id")
            hub_kind = (modeled_hub.get("kind") or "").lower()

            if "routeserver" in hub_kind:
                # ARM sets "kind": "RouteServer" on virtualHubs resources created via the
                # standalone Route Server experience — this is Microsoft's own discriminator
                # for the same UI/API ambiguity, so it takes priority over virtualWan/connection
                # checks below (a Route Server can still be given a hubVirtualNetworkConnection
                # manually, but it's still a Route Server).
                route_servers.append(modeled_hub)
            elif virtual_wan_id:
                virtual_hubs_by_wan.setdefault(virtual_wan_id, []).append(modeled_hub)
            elif modeled_hub.get("id") in hub_ids_with_vnet_connections:
                # No parent Virtual WAN, no "kind" marker, but has hub-to-VNet connections
                # wired up — a real (if unusually detached) vHub rather than a Route Server.
                orphaned_virtual_hubs.append(modeled_hub)
            else:
                # Fallback for hubs with neither a virtualWan nor a "kind" marker (e.g. an
                # older Route Server provisioned before ARM added "kind"): treat "no WAN, no
                # connections" as a standalone Route Server.
                route_servers.append(modeled_hub)

        subnet_connections = {}

        for nic in network_interfaces:
            for ip_config in nic.get("properties", {}).get("ipConfigurations", []):
                subnet_id = ((ip_config.get("properties") or {}).get("subnet") or {}).get("id")
                if not subnet_id:
                    continue
                subnet_connections.setdefault(subnet_id, []).append(
                    self.build_connected_device_from_nic(nic, ip_config, public_ip_lookup)
                )

        for private_endpoint in private_endpoints:
            subnet_id = ((private_endpoint.get("properties") or {}).get("subnet") or {}).get("id")
            if not subnet_id:
                continue
            subnet_connections.setdefault(subnet_id, []).append(
                self.build_connected_device_from_private_endpoint(private_endpoint)
            )

        modeled_vnets = []
        for vnet in virtual_networks:
            props = vnet.get("properties", {})
            subnets = []
            for subnet in props.get("subnets", []):
                subnets.append(self.build_subnet(subnet, subnet_connections.get(subnet.get("id"), [])))

            modeled_vnets.append({
                "id": vnet.get("id"),
                "name": vnet.get("name"),
                "region": vnet.get("location"),
                "address_spaces": (props.get("addressSpace") or {}).get("addressPrefixes", []),
                "dns_servers": (props.get("dhcpOptions") or {}).get("dnsServers", []),
                "enable_ddos_protection": props.get("enableDdosProtection"),
                "ddos_protection_plan_id": (props.get("ddosProtectionPlan") or {}).get("id"),
                "subnets": subnets,
                "peerings": [self.build_peering(peering) for peering in props.get("virtualNetworkPeerings", [])],
            })

        return {
            "id": subscription_id,
            "name": subscription.get("displayName"),
            "state": subscription.get("state"),
            "public_ip_addresses": list(public_ip_lookup.values()),
            "network_security_groups": [
                self.build_network_security_group(nsg) for nsg in network_security_groups
            ],
            "route_tables": [
                self.build_route_table(route_table) for route_table in route_tables
            ],
            "nat_gateways": [
                self.build_nat_gateway(nat_gateway) for nat_gateway in nat_gateways
            ],
            "load_balancers": [
                self.build_load_balancer(load_balancer) for load_balancer in load_balancers
            ],
            "application_gateways": [
                self.build_application_gateway(application_gateway) for application_gateway in application_gateways
            ],
            "virtual_network_gateways": [
                self.build_virtual_network_gateway(gateway) for gateway in virtual_network_gateways
            ],
            "local_network_gateways": [
                self.build_local_network_gateway(gateway) for gateway in local_network_gateways
            ],
            "virtual_wans": [
                self.build_virtual_wan(virtual_wan, virtual_hubs_by_wan.get(virtual_wan.get("id"), []))
                for virtual_wan in virtual_wans
            ],
            "orphaned_virtual_hubs": orphaned_virtual_hubs,
            "route_servers": route_servers,
            "virtual_hub_vnet_connections": [
                self.build_virtual_hub_vnet_connection(connection)
                for connection in virtual_hub_vnet_connections
            ],
            "virtual_networks": modeled_vnets,
        }

    def build_network_model(self):
        status.set_phase("Collecting subscriptions")
        subscriptions = self.collect_values(self.get_all_subscriptions(), label="subscriptions")

        return {
            "tenant_id": tokenizer.get_current_tenant_id(),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "subscriptions": [self.collect_subscription_network_model(subscription) for subscription in subscriptions],
        }

    def run(self):
        status.set_phase("Modeling Azure network topology")
        network_model = self.build_network_model()
        write_json_payload_to_disk(network_model, source_name=self.droplet_name)
        return network_model
