const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let backend;
let win;

function startBackend() {
  const script = path.join(__dirname, 'backend.py');
  const command = process.env.FORENSIC_PYTHON || (process.platform === 'win32' ? 'py' : 'python3');
  const args = process.env.FORENSIC_PYTHON_ARGS
    ? process.env.FORENSIC_PYTHON_ARGS.split(' ')
    : (process.platform === 'win32' && command === 'py' ? ['-3'] : []);

  backend = spawn(command, [...args, script], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  backend.stdout.setEncoding('utf8');
  let buffer = '';
  backend.stdout.on('data', (chunk) => {
    buffer += chunk;
    let newline;
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      try {
        if (win && !win.isDestroyed()) win.webContents.send('backend-message', JSON.parse(line));
      } catch (error) {
        console.error('Ignoring invalid backend message:', error.message);
      }
    }
  });
  backend.stderr.setEncoding('utf8');
  backend.stderr.on('data', (chunk) => console.error(`[backend] ${chunk.trimEnd()}`));
  backend.on('error', (error) => console.error(`Could not start Python backend (${command}):`, error.message));
  backend.on('exit', (code, signal) => {
    if (code !== 0 && code !== null) console.error(`Python backend exited with code ${code}`);
    if (signal) console.info(`Python backend stopped (${signal})`);
  });
}

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 1480,
    height: 900,
    minWidth: 980,
    minHeight: 620,
    show: false,
    backgroundColor: '#09090b',
    icon: path.join(__dirname, 'resources', 'cld-task-manager.ico'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.once('ready-to-show', () => win.show());
  win.loadFile(path.join(__dirname, 'index.html'));
  startBackend();
});

ipcMain.on('command', (event, command) => {
  if (!win || event.sender !== win.webContents || !command || typeof command !== 'object') return;
  if (command.cmd === 'reveal' && typeof command.path === 'string') {
    shell.showItemInFolder(command.path);
    return;
  }
  if (command.cmd === 'kill' && Number.isSafeInteger(command.pid) && command.pid > 0 && backend?.stdin.writable) {
    backend.stdin.write(`${JSON.stringify({ cmd: 'kill', pid: command.pid, tree: command.tree === true })}\n`);
  }
});

app.on('window-all-closed', () => {
  if (backend && !backend.killed) backend.kill();
  app.quit();
});

app.on('before-quit', () => {
  if (backend && !backend.killed) backend.kill();
});
