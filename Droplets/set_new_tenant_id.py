import util.console as console
import util.tokenizer as tokenizer

class Droplet:
    droplet_name = "Settings: Set tenant ID"
    droplet_type = 'settings' #Change to scan / settings / util / test as needed.
    droplet_path = None
    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def run(self):
        tenant_id = tokenizer.set_new_tenant_id()
        console.success("[✓] Saved tenant ID: %s" % tenant_id)

