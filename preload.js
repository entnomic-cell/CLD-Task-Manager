const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  onMessage: (callback) => {
    if (typeof callback !== 'function') return;
    ipcRenderer.on('backend-message', (_event, message) => callback(message));
  },
  sendCommand: (command) => ipcRenderer.send('command', command),
});
