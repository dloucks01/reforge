"""Make the repo root importable so `import reforge` works without install.

Also isolate QSettings to a throwaway config dir for the whole test session, so
the GUI's remembered-settings feature never reads or writes the developer's real
~/.config during tests.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Redirect QSettings (and any XDG config) to a temp dir before Qt starts.
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="reforge-test-cfg-")
