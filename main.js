const { app, BrowserWindow } = require('electron');

function createWindow () {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
  });
  mainWindow.removeMenu();
  mainWindow.loadFile('index.html'); 
  mainWindow.setIcon('FB_IMG_1729874984263.ico');
}

app.whenReady().then(createWindow);