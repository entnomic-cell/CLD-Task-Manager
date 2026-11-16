# CLD Task Manager

A standalone Windows desktop utility for viewing process details and live CPU, memory, disk, and network activity. Its Processes, Details, and Performance tabs run horizontally across the top with animated active and hover states. Its forensic view periodically searches selected Windows service and process memory for executable, library, archive, and `file:///` path strings, and scans those selected processes with the bundled YARA Forge core rules. Process details include extracted executable icons, publisher metadata, Authenticode status, signer, and YARA matches.

## Development

Requirements: Windows 10 or newer, Node.js 20+, npm, Python 3.10+, and the Python packages in `requirements.txt` (`psutil` and `yara-python`).

```powershell
cd forensic-task-manager
py -3 -m pip install -r requirements.txt
npm install
npm start
```

The Details view extracts each executable's icon and shows publisher metadata, digital-signature status and signer, and YARA memory matches for the selected system processes. The bundled YARA Forge core snapshot is dated 2026-11-15. Service-memory reads and YARA matches may be incomplete unless the app is started with the permissions Windows requires.

The Details view can end a process or process tree and open the executable's folder. Ending a system process can make Windows or other applications unstable.

## Build a portable Windows app

```powershell
cd forensic-task-manager
npm install
npm run dist
```

The portable executable is written to `dist/`. The app still needs Python 3, `psutil`, and `yara-python` on the computer where it runs. If Python is installed outside the standard Windows launcher, set `FORENSIC_PYTHON` to the interpreter path. `FORENSIC_PYTHON_ARGS` can provide optional interpreter arguments.

The project is Windows-only because the backend uses Windows process-memory APIs and Windows service discovery.
