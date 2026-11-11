# Install the engine

SealBox has two parts: this extension and a small Python command-line engine that does the
actual work (scanning, encryption, approval dialogs). Install the engine once per computer.

**Recommended (isolated install):**

```sh
pipx install sealbox
```

**Or with pip:**

```sh
python -m pip install --user sealbox
```

Requirements: Python 3.12 or newer. On Linux, the approval dialog needs Tk
(`sudo apt install python3-tk` on Debian/Ubuntu).

If `sealbox` is installed somewhere unusual, set **SealBox: Executable** in Settings.
