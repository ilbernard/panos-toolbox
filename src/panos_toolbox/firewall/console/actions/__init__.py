"""Action plugins. Every module in this package is imported by ``discover()``.

To add an action: create ``actions/<name>.py`` with an ``Action`` subclass decorated
with ``@register`` (see ``reboot.py``). No other registration is needed.
"""
import importlib
import pkgutil

from ..core.actions import registry


def discover():
    """Import all action modules (registering them) and return the registry."""
    for module in pkgutil.iter_modules(__path__):
        if not module.name.startswith("_"):
            importlib.import_module(f"{__name__}.{module.name}")
    return registry
