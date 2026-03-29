"""Plugin auto-discovery: scans this directory and loads any class that subclasses BodyTransformPlugin."""

import os
import importlib
import inspect

from .base import BodyTransformPlugin


def discover_plugins():
    """Scan the plugins directory for modules containing BodyTransformPlugin subclasses.

    Returns a list of plugin classes (not instances).
    """
    plugin_classes = []
    plugins_dir = os.path.dirname(os.path.abspath(__file__))

    for filename in sorted(os.listdir(plugins_dir)):
        if filename.startswith('_') or not filename.endswith('.py'):
            continue
        if filename == 'base.py':
            continue

        module_name = filename[:-3]
        try:
            module = importlib.import_module('.' + module_name, package=__name__)
        except Exception as e:
            print("[PluginLoader] Failed to import %s: %s" % (module_name, e))
            continue

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (inspect.isclass(attr)
                    and issubclass(attr, BodyTransformPlugin)
                    and attr is not BodyTransformPlugin):
                plugin_classes.append(attr)

    return plugin_classes
