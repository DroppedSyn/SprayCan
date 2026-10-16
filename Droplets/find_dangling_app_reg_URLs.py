import json
import socket
from urllib.parse import urlparse

import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, make_finding, make_object, write_findings_to_disk

class Droplet:
    droplet_name = "Scan: Dangling app-reg URLS"
    droplet_type = "scan"
    droplet_path = None
    droplet_description = (
        "Enumerates all application registrations and checks redirect URIs and\n"
        "reply URLs for domains that no longer resolve. An unregistered domain\n"
        "in a redirect URI can be hijacked to intercept OAuth authorization codes.\n"
        "\n"
        "Requires\n"
        "  Graph : Application.Read.All"
    )
    def __init__(self, droplet_path):
        self.droplet_path = droplet_path
        self.findings = []
        self.graph_token = None

    def get_graph_headers(self):
        if not self.graph_token:
            self.graph_token = tokenizer.get_graph_token()
        return {
            'Authorization': 'Bearer %s' % self.graph_token,
            'Content-Type': 'application/json',
        }

    def graph_get_json(self, path):
        full_url = "https://graph.microsoft.com%s" % path
        response = http_client.get(url=full_url, headers=self.get_graph_headers())
        return json.loads(response.content or "{}")

    def collect_graph_values(self, path):
        json_res = self.graph_get_json(path)
        if 'value' in json_res:
            return check_pagination(self.graph_token, json_res, json_res['value'])
        return []

    def get_all_apps(self):
        """
        Queries the Graph API for all application registrations and returns them.
        :return:
        """
        status.set_phase("Collecting application registrations")
        return self.collect_graph_values("/v1.0/applications")

    def get_domain(self, url):
        # hostname, not netloc: a port or userinfo in the URI would otherwise make the
        # DNS lookup fail and the URI be reported as dangling.
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return (parsed.hostname or parsed.path.split("/")[0]).lower()

    def is_app_service_host(self, redirect_uri):
        domain = self.get_domain(redirect_uri)
        return domain == "azurewebsites.net" or domain.endswith(".azurewebsites.net")

    def is_wildcard_redirect_uri(self, redirect_uri):
        return "*" in self.get_domain(redirect_uri)

    def is_dangling_redirect_uri(self, redirect_uri):
        # Wildcard hosts never resolve; they are reported separately, not as dangling.
        if not self.is_app_service_host(redirect_uri) or self.is_wildcard_redirect_uri(redirect_uri):
            return False

        try:
            socket.getaddrinfo(self.get_domain(redirect_uri), 0, 0, 0, 0)
            return False
        except OSError:
            return True

    def build_finding(self, app, dangling_uris):
        return make_finding(
            title="Dangling App Registration Redirect URI%s" % ("" if len(dangling_uris) == 1 else "s"),
            desc=(
                "One or more application redirect URIs point to an azurewebsites.net host that no "
                "longer resolves. This can indicate a dangling app registration URL."
            ),
            severity="high",
            confidence="high",
            objects=[make_object("application", app.get("id"), app.get("displayName"))],
            rec=(
                "Remove the stale redirect URIs or recreate the backing Azure App Service if still intended."
            ),
            evidence=[
                {
                    "redirect_uri": uri,
                    "resolved_domain": self.get_domain(uri),
                    "resolution_status": "unresolvable",
                }
                for uri in dangling_uris
            ],
            meta={
                "scan": self.droplet_name,
                "app_id": app.get("id"),
                "app_name": app.get("displayName"),
            },
        )

    def build_wildcard_finding(self, app, wildcard_uris):
        return make_finding(
            title="Wildcard App Service Redirect URI%s" % ("" if len(wildcard_uris) == 1 else "s"),
            desc=(
                "One or more application redirect URIs use a wildcard azurewebsites.net host. Anyone can "
                "create an App Service under azurewebsites.net, so a matching host can be registered to "
                "receive this application's authorization codes or tokens."
            ),
            severity="high",
            confidence="high",
            objects=[make_object("application", app.get("id"), app.get("displayName"))],
            rec="Replace wildcard redirect URIs with the exact hosts the application uses.",
            evidence=[
                {
                    "redirect_uri": uri,
                    "resolved_domain": self.get_domain(uri),
                    "resolution_status": "wildcard",
                }
                for uri in wildcard_uris
            ],
            meta={
                "scan": self.droplet_name,
                "app_id": app.get("id"),
                "app_name": app.get("displayName"),
            },
        )

    def get_redirect_uris(self, app):
        redirect_uris = []
        for platform in ('web', 'spa', 'publicClient'):
            redirect_uris.extend((app.get(platform) or {}).get('redirectUris') or [])
        return redirect_uris

    def find_vulnerable_apps(self, apps):
        findings = []
        status.set_phase("Analyzing application redirect URIs")

        for app in apps:
            redirect_uris = self.get_redirect_uris(app)

            dangling_uris = [uri for uri in redirect_uris if self.is_dangling_redirect_uri(uri)]
            if dangling_uris:
                findings.append(self.build_finding(app, dangling_uris))

            wildcard_uris = [
                uri for uri in redirect_uris
                if self.is_app_service_host(uri) and self.is_wildcard_redirect_uri(uri)
            ]
            if wildcard_uris:
                findings.append(self.build_wildcard_finding(app, wildcard_uris))

        return findings

    def run(self):
        apps = self.get_all_apps()

        status.set_phase("Checking %s applications for dangling redirect URIs" % len(apps))
        self.findings = self.find_vulnerable_apps(apps)
        status.set_phase("Writing %s dangling app registration findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)

        return self.findings
