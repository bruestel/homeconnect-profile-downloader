const { app, BrowserWindow, session, ipcMain, Menu } = require('electron');
const crypto = require('crypto');
const fetch = require('node-fetch');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const JSZip = require('jszip');


let mainWindow;

const clientId = '9B75AC9EC512F36C84256AC47D813E2C1DD0D6520DF774B020E1E6E2EB29B1F3';
const redirectUri = 'hcauth://auth/prod';
const scope = 'Control DeleteAppliance IdentifyAppliance Images Monitor ReadAccount ReadOrigApi Settings WriteAppliance WriteOrigApi';
const filter = {
  urls: ["*://*/auth/prod*",],
};

let tokenUrl;
let accountDetailsUrl;
let deviceInfoUrl;
let codeVerifier;
let target;


const createWindow = () => {
  mainWindow = new BrowserWindow({
    width: 768,
    height: 768,
    webPreferences: {
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  })

  mainWindow.loadFile('index.html');

  // menu
  const menuTemplate = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Go to Start Page',
          click: () => {
            mainWindow.loadFile(path.join(__dirname, 'index.html'));
          },
        },
        { type: 'separator' },
        { label: 'Quit', role: 'quit' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { label: 'Toggle Developer Tools', role: 'toggleDevTools' },
        { type: 'separator' },
        { label: 'Actual Size', role: 'resetZoom' },
        { label: 'Zoom In', role: 'zoomIn' },
        { label: 'Zoom Out', role: 'zoomOut' },
      ],
    }
  ];
  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);

  ipcMain.handle('get-zip-files', async () => {
    const downloadsFolder = path.join(app.getPath('userData'), "profiles-homeconnectdirect");
    try {
      const files = fs.readdirSync(downloadsFolder);
      const zipFiles = files
        .filter(file => path.extname(file).toLowerCase() === '.zip')
        .map(file => {
          const filePath = path.join(downloadsFolder, file);
          const stats = fs.statSync(filePath);
          return { file, ctime: stats.ctime };
        });

      zipFiles.sort((a, b) => b.ctime - a.ctime);
      return zipFiles.map(entry => entry.file);

    } catch (error) {
      console.error('Could not read zip files:', error.message);
      return [];
    }
  });

  ipcMain.handle('get-profile-path', async () => {
    return path.join(app.getPath('userData'), "profiles-homeconnectdirect");
  });

  ipcMain.on('form-submitted', (event, data) => {
    console.log('Fetch profiles.', data);

    let apiBaseUrl;
    let assetBaseUrl;
    if (data.region === 'EU') {
      apiBaseUrl = "https://api.home-connect.com";
      assetBaseUrl = 'https://prod.reu.rest.homeconnectegw.com';
    } else if (data.region === 'NA') {
      apiBaseUrl = "https://api-rna.home-connect.com";
      assetBaseUrl = 'https://prod.rna.rest.homeconnectegw.com';
    } else if (data.region === 'CN') {
      apiBaseUrl = "https://api.home-connect.cn";
      assetBaseUrl = 'https://prod.rgc.rest.homeconnectegw.cn';
    } else if (data.region === 'RU') {
      apiBaseUrl = "https://api-rus.home-connect.com";
      assetBaseUrl = 'https://prod.rus.rest.homeconnectegw.com';
    } else {
      throw new Error(`Invalid region! ${data.region}`);
    }

    target = data.target;

    const authorizeUrl = apiBaseUrl + '/security/oauth/authorize';
    tokenUrl = apiBaseUrl + '/security/oauth/token';
    accountDetailsUrl = assetBaseUrl + '/account/details';
    deviceInfoUrl = assetBaseUrl + '/api/iddf/v1/iddf/';

    const nonce = generateNonce(16);
    const state = generateNonce(16);
    codeVerifier = generateNonce(32);
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // build url
    const queryParams = {
      redirect_url: redirectUri,
      client_id: clientId,
      response_type: "code",
      prompt: 'login',
      code_challenge_method: 'S256',
      code_challenge: codeChallenge,
      state: state,
      nonce: nonce,
      scope: scope
    };
    const url = new URL(authorizeUrl);
    Object.keys(queryParams).forEach(key => {
      url.searchParams.append(key, queryParams[key]);
    });

    //mainWindow.webContents.openDevTools();
    mainWindow.loadURL(url.toString());
  });

  // capture auth code response
  session.defaultSession.webRequest.onBeforeRequest(filter, (details, callback) => {
    console.log(`Captured auth request: ${details.url}`);
    const url = new URL(details.url);
    const queryParams = url.searchParams;
    const code = queryParams.get("code");

    callback({
      cancel: true
    });

    mainWindow.loadFile('loading.html');


    // get access token and fetch device information
    const targetDirectory = "profiles-" + target;
    getDeviceInformation(tokenUrl, code, codeVerifier, accountDetailsUrl, deviceInfoUrl, targetDirectory);
  });
}

app.whenReady().then(() => {
  session.defaultSession.setUserAgent('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36');

  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})


app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

function generateNonce(length) {
  return crypto.randomBytes(length).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return hash;
}

async function getDeviceInformation(tokenUrl, code, codeVerifier, accountDetailsUrl, deviceInfoUrl, targetDirectory) {
  const accessToken = await getOAuthToken(tokenUrl, code, codeVerifier);

  // profiles
  const response = await getApplianceInformation(accountDetailsUrl, accessToken);
  const homeAppliances = response.data.homeAppliances;
  const profiles = [];
  for (const appliance of homeAppliances) {
    console.log(`haId: ${appliance.identifier}, type: ${appliance.type}, serialNumber: ${appliance.serialnumber}`);

    const profile = {
      haId: appliance.identifier,
      type: appliance.type,
      serialNumber: appliance.serialnumber,
      featureMappingFileName: appliance.identifier + "_FeatureMapping.xml",
      deviceDescriptionFileName: appliance.identifier + "_DeviceDescription.xml",
      created: generateTimestamp()
    }

    if (appliance.hasOwnProperty("tls") && appliance.tls !== undefined && appliance.tls.key !== undefined) {
      console.log(`TLS key: ${appliance.tls.key}`);
      profile["connectionType"] = "TLS";
      profile["key"] = appliance.tls.key;
    } else {
      console.log(`AES key: ${appliance.aes.key}, iv: ${appliance.aes.iv}`);
      profile["connectionType"] = "AES";
      profile["key"] = appliance.aes.key;
      profile["iv"] = appliance.aes.iv;
    }

    profiles.push(profile);

    // get device xmls
    await loadZip(deviceInfoUrl, accessToken, targetDirectory, profile);
  }

  mainWindow.loadFile('download.html');
}

async function getOAuthToken(url, code, codeVerifier) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code_verifier: codeVerifier,
    code: code,
    redirect_uri: redirectUri,
  });

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      throw new Error(`HTTP-Error: ${response.status}`);
    }

    const data = await response.json();
    console.log('Token response:', data);
    return data.access_token;
  } catch (error) {
    console.error('Could not fetch token:', error);
  }
}

async function getApplianceInformation(url, accessToken) {
  console.log('Get appliance information. ', accessToken, url);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP-Error: ${response.status}`);
    }

    const data = await response.json();
    console.log('appliance information response:', data);
    return data;
  } catch (error) {
    console.error('Could not fetch appliance information:', error);
  }
}

async function loadZip(urlPrefix, accessToken, targetDirectory, profile) {
  try {
    const folderPath = path.join(app.getPath('userData'), targetDirectory);
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
      console.log(`Created target directory: ${folderPath}`);
    }

    const now = Date.now();
    const zipFilePath = path.join(folderPath, profile.haId + '_' + now + '.zip');
    const headers = {
      'Authorization': 'Bearer ' + accessToken
    };
    const url = urlPrefix + profile.haId;
    console.log(`Loading appliance XMLs... (${url})`);
    const response = await axios.get(url, { responseType: 'arraybuffer', headers });

    const zip = new JSZip();
    await zip.loadAsync(response.data);
    console.log('Original ZIP loaded.');

    zip.file(`${profile.haId}.json`, JSON.stringify(profile, null, 2));

    const modifiedZipContent = await zip.generateAsync({ type: 'nodebuffer' });
    fs.writeFileSync(zipFilePath, modifiedZipContent);
  
    console.log(`Modified ZIP saved: ${zipFilePath}`);
  
    return zipFilePath;
  } catch (error) {
    console.error('Could not load or write profile zip:', error.message);
  }
}

function generateTimestamp() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  const milliseconds = String(now.getMilliseconds()).padStart(3, '0');

  const nanoseconds = `${milliseconds}000000`;

  const offsetMinutes = now.getTimezoneOffset();
  const offsetHours = Math.floor(Math.abs(offsetMinutes) / 60);
  const offsetMinutesPart = Math.abs(offsetMinutes) % 60;
  const offsetSign = offsetMinutes > 0 ? '-' : '+';
  const timezone = `${offsetSign}${String(offsetHours).padStart(2, '0')}:${String(offsetMinutesPart).padStart(2, '0')}`;

  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${nanoseconds}${timezone}`;
}