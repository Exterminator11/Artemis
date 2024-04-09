const { app, BrowserWindow } = require('electron')
const {spawn,exec}=require('child_process')
const path = require('path')
const fs=require('fs')
const { ipcMain } = require('electron')

function createWindow () {
  const win = new BrowserWindow({
    width: 1100,
    height: 750,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: true,
      contextIsolation: false
    }
  })

  ipcMain.on('navigate',(event,arg)=>{
    win.loadFile(arg)
  })

  if(fs.existsSync('/Users/rachitdas/Desktop/Artemis.ai/final-a/src/user.json')){
    fs.readFile('/Users/rachitdas/Desktop/Artemis.ai/final-a/src/user.json',(err,data)=>{
      console.log(data.toString())
    })
    win.loadFile('/Users/rachitdas/Desktop/Artemis.ai/final-a/src/tptp.html')
  }
  else{
    win.loadFile('/Users/rachitdas/Desktop/Artemis.ai/final-a/src/login.html')

  }

}
app.whenReady().then(() => {
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})