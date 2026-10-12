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
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.netloc or parsed.path.split("/")[0]

    def is_dangling_redirect_uri(self, redirect_uri):
        if "azurewebsites.net" not in redirect_uri:
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

    def find_vulnerable_apps(self, apps):
        findings = []
        status.set_phase("Analyzing application redirect URIs")

        for app in apps:
            redirect_uris = []
            redirect_uris.extend((app.get('web') or {}).get('redirectUris', []))
            redirect_uris.extend((app.get('publicClient') or {}).get('redirectUris', []))

            dangling_uris = [uri for uri in redirect_uris if self.is_dangling_redirect_uri(uri)]
            if dangling_uris:
                findings.append(self.build_finding(app, dangling_uris))

        return findings

    def run(self):
        apps = self.get_all_apps()

        status.set_phase("Checking %s applications for dangling redirect URIs" % len(apps))
        self.findings = self.find_vulnerable_apps(apps)
        status.set_phase("Writing %s dangling app registration findings" % len(self.findings))
        write_findings_to_disk(self.findings, source_name=self.droplet_name)

        return self.findings
