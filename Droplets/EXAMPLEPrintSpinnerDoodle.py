class Droplet:
    droplet_name = "Example Module: Print Spinner Doodle"
    droplet_type = "test"
    droplet_path = None
    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def run(self):
        print("%s Running." % self.droplet_name)
