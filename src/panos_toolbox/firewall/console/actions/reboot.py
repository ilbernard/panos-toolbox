"""Reboot the selected firewalls through Panorama (``request restart system``)."""
from ..core.actions import Action, Confirmation, register

CONFIRM_WORD = "REBOOT"


@register
class RebootAction(Action):
    id = "reboot"
    label = "Reboot"
    description = "Restart the selected firewalls (request restart system) through Panorama."
    destructive = True
    order = 900

    def available_for(self, device):
        if not device.connected:
            return "not connected to Panorama, the command cannot be proxied"
        return None

    def confirmation(self, devices):
        lines = [f"  {d.display_name}  ({d.serial})" for d in devices]
        text = f"The following {len(devices)} firewall(s) will be rebooted:\n\n" + "\n".join(lines)
        active = [d.display_name for d in devices if d.ha_state.lower() == "active"]
        if active:
            text += (
                "\n\nHA active member(s), a failover will occur: " + ", ".join(active) + "."
            )
        text += "\n\nTraffic through these firewalls will be interrupted."
        return Confirmation(
            title="Confirm reboot",
            text=text,
            require_typed=CONFIRM_WORD if len(devices) > 1 else None,
        )

    def run(self, session, device):
        session.restart_device(device.serial)
        return "reboot command sent (not yet verified, refresh to check the device state)"
