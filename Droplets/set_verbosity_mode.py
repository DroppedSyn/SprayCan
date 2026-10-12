from InquirerPy import inquirer

import util.console as console
import util.settings as settings


class Droplet:
    droplet_name = "Settings: Set verbosity mode"
    droplet_type = "settings"
    droplet_path = None

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def run(self):
        current_mode = settings.get_verbosity()
        selected_mode = inquirer.select(
            message="Verbosity mode",
            choices=[
                {"name": "Quiet", "value": "quiet"},
                {"name": "Normal", "value": "normal"},
                {"name": "Debug", "value": "debug"},
            ],
            default=current_mode,
            instruction="Current mode: %s" % current_mode,
        ).execute()
        settings.set_verbosity(selected_mode)
        console.success("[✓] Verbosity set to: %s" % selected_mode)
