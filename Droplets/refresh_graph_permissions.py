import Objects.Core as Core

class Droplet:
    droplet_name = "Refresh and update Graph Permissions"
    droplet_type = 'settings' #Change to scan / settings / util / test as needed.
    droplet_path = None
    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def run(self):
        Core.persist_graph_permissions_to_disk()
