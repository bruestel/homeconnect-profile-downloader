const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  sendFormData: (data) => {
    ipcRenderer.send('form-submitted', data);
  },
  getZipFiles: () => ipcRenderer.invoke('get-zip-files'),
  getProfilePath: () => ipcRenderer.invoke('get-profile-path'),
});

ipcRenderer.on('app-log', (event, message) => {
  console.log(message);
});

ipcRenderer.on('error-details', (event, message) => {
  document.getElementById('error-text').textContent = message;
});
