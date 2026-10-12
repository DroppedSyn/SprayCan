class Droplet:
    def __init__(self, droplet_path):
        self.droplet_path = droplet_path  # Instance variable

    def run(self):
        raise NotImplementedError("Each plugin must implement its own run()")