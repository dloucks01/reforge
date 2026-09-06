# Packaging — copy-and-run bundle (no installation)

Reforge is delivered as a self-contained tarball. Nothing is installed on the
target: the Python runtime, Scapy, PySide6/Qt, and Reforge are bundled.

Build it:

```bash
packaging/build_bundle.sh
```

This runs PyInstaller (`reforge.spec`, onedir) and produces
`reforge-<version>-linux-<arch>.tar.gz` plus a `.sha256`. Transfer, verify,
extract, and run `reforge/reforge`. See ../docs/DEPLOYMENT.md for the full
airgap workflow.

Files:
- `reforge.spec`   — PyInstaller spec (bundles Scapy + PySide6 + reforge)
- `launch.py`      — frozen entry point (calls the Reforge CLI)
- `build_bundle.sh`— build + tar + checksum
