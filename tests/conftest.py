import importlib.util
import os

# GUI tests run on Qt's offscreen platform, so no display is needed (CI, SSH, containers).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

collect_ignore = []
if importlib.util.find_spec("PySide6") is None:  # optional dependency: .[console]
    collect_ignore.append("test_console_gui.py")
