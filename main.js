const { app, BrowserWindow, session, ipcMain, Menu } = require('electron');
const crypto = require('crypto');
const fetch = require('node-fetch');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const JSZip = require('jszip');
const xml2js = require('xml2js');

app.commandLine.appendSwitch('password-store', 'basic');
app.commandLine.appendSwitch('disable-features', 'NativeNotifications');

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
    width: 900,
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
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
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

  ipcMain.handle('get-files', async () => {
    const downloadsFolder = getDownloadDirectory();
    try {
      const files = fs.readdirSync(downloadsFolder);
      const filteredFiles = files
        .filter(file => path.extname(file).toLowerCase() === '.zip' || path.extname(file).toLowerCase() === '.json')
        .map(file => {
          const filePath = path.join(downloadsFolder, file);
          const stats = fs.statSync(filePath);
          return { file, ctime: stats.ctime };
        });

      filteredFiles.sort((a, b) => b.ctime - a.ctime);
      return filteredFiles.map(entry => entry.file);

    } catch (error) {
      console.error('Could not read files:', error.message);
      mainWindow.webContents.send('app-log', `Could not read files ${error.message}`);
      return [];
    }
  });

  ipcMain.handle('get-profile-path', async () => {
    return getDownloadDirectory();
  });

  ipcMain.on('form-submitted', (event, data) => {
    console.log('Fetch profiles.', data);
    mainWindow.webContents.send('app-log', `Fetch profiles: ${JSON.stringify(data)}`);

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
    fetchDeviceData(tokenUrl, code, codeVerifier, accountDetailsUrl, deviceInfoUrl, target);
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

async function fetchDeviceData(tokenUrl, code, codeVerifier, accountDetailsUrl, deviceInfoUrl, target) {
  try {
    const accessToken = await getOAuthToken(tokenUrl, code, codeVerifier);

    // profiles
    const response = await getApplianceInformation(accountDetailsUrl, accessToken);
    const homeAppliances = response.data.homeAppliances;

    if ((target === 'hcpy')) {
      const devices = [];
      for (const appliance of homeAppliances) {
        console.log(`haId: ${appliance.identifier}, type: ${appliance.type}, serialNumber: ${appliance.serialnumber}`);
        console.log(`appliance: ${JSON.stringify(appliance, null, 2)}`);

        const config = new Map();
        config.set('name', appliance.type.toLowerCase());
        if (appliance.hasOwnProperty("tls") && appliance.tls !== undefined) {
          config.set('key', appliance.tls.key);
          config.set('host', `${appliance.brand}-${appliance.type}-${appliance.identifier}`);
        } else {
          config.set('key', appliance.aes.key);
          config.set('iv', appliance.aes.iv);
          config.set('host', appliance.identifier);
        }

        await fetchApplianceInformationAndExtendHcpyConfig(deviceInfoUrl, accessToken, config, appliance.identifier);
        devices.push(config);
      }

      if (devices.length === 0) {
        throw new Error("No appliances found for this account!");
      }

      await writeHcpyConfig(devices);
    } else {
      const profiles = [];
      for (const appliance of homeAppliances) {
        console.log(`haId: ${appliance.identifier}, type: ${appliance.type}, serialNumber: ${appliance.serialnumber}`);
        console.log(`appliance: ${JSON.stringify(appliance, null, 2)}`);

        const profile = {
          haId: appliance.identifier,
          type: appliance.type,
          serialNumber: appliance.serialnumber,
          brand: appliance.brand,
          vib: appliance.vib,
          mac: appliance.mac,
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

        await fetchApplianceInformationAndWriteProfile(deviceInfoUrl, accessToken, profile, target);
      }

      if (profiles.length === 0) {
        throw new Error("No appliances found for this account!");
      }
    }
    mainWindow.loadFile('download.html');
  } catch (error) {
    mainWindow.loadFile('error.html');

    mainWindow.webContents.once('did-finish-load', () => {
      mainWindow.webContents.send('error-details', error.message);
    });
  }
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
      throw new Error(`Invalid HTTP response received: ${response.status}`);
    }

    const data = await response.json();
    console.log('Token response:', data);
    return data.access_token;
  } catch (error) {
    console.error('Could not fetch token:', error);
    mainWindow.webContents.send('app-log', `Could not fetch token: ${error}`);
    throw error;
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

    if (response.status == 401) {
      throw new URIError("Wrong region used! Try a different region.");
    } else if (!response.ok) {
      throw new Error(`Invalid server response code! Received: ${response.status}`);
    }

    const data = await response.json();
    console.log('appliance information response:', data);
    return data;
  } catch (error) {
    console.error('Could not fetch appliance information:', error);
    mainWindow.webContents.send('app-log', `Could not fetch appliance information: ${error}`);
    throw error;
  }
}

async function fetchApplianceInformationZip(urlPrefix, accessToken, haId) {
  const headers = {
    'Authorization': 'Bearer ' + accessToken
  };
  const url = urlPrefix + haId;
  console.log(`Loading appliance XMLs... (${url})`);
  const response = await axios.get(url, { responseType: 'arraybuffer', headers });

  const zip = new JSZip();
  await zip.loadAsync(response.data);
  console.log('Original ZIP loaded.');

  return zip;
}

async function fetchApplianceInformationAndExtendHcpyConfig(urlPrefix, accessToken, config, haId) {
  try {
    const zip = await fetchApplianceInformationZip(urlPrefix, accessToken, haId);

    // find xml files
    let deviceDescriptionXml = null;
    let featureMappingXml = null;

    zip.forEach((relativePath, file) => {
      if (relativePath.endsWith('_DeviceDescription.xml')) {
        deviceDescriptionXml = file;
      } else if (relativePath.endsWith('_FeatureMapping.xml')) {
        featureMappingXml = file;
      }
    });

    if (deviceDescriptionXml && featureMappingXml) {
      const deviceDescContent = await deviceDescriptionXml.async('text');
      const featureMappingContent = await featureMappingXml.async('text');

      const parser = new xml2js.Parser();

      const featureData = await parser.parseStringPromise(featureMappingContent);
      const descData = await parser.parseStringPromise(deviceDescContent);

      const features = {};
      const enums = {};

      // parse enumerations
      if (featureData.featureMappingFile.enumDescriptionList?.[0]?.enumDescription) {
        for (const enumDesc of featureData.featureMappingFile.enumDescriptionList[0].enumDescription) {
          const enumId = parseInt(enumDesc.$.refENID, 16);
          const values = {};

          if (enumDesc.enumMember) {
            for (const member of enumDesc.enumMember) {
              values[parseInt(member.$.refValue)] = member._;
            }
          }

          enums[enumId] = {
            name: enumDesc.$.enumKey,
            values: values
          };
        }
      }

      // parse features
      if (featureData.featureMappingFile.featureDescription?.[0]?.feature) {
        for (const feature of featureData.featureMappingFile.featureDescription[0].feature) {
          const uid = parseInt(feature.$.refUID, 16);
          features[uid] = {
            name: feature._
          };
        }
      }

      // parse description elements and merge with features
      const parseXmlList = (entries, depth = 0) => {
        for (const entry of entries) {
          if (entry.$ && entry.$.uid) {
            const uid = parseInt(entry.$.uid, 16);

            if (features[uid] && depth > 1) {
              // Only add attributes for elements that are NOT direct children of device
              Object.assign(features[uid], entry.$);

              if (entry.$.enumerationType) {
                const enumId = parseInt(entry.$.enumerationType, 16);
                if (enums[enumId]) {
                  features[uid].values = enums[enumId].values;
                }
                delete features[uid].enumerationType;
              }

              delete features[uid].uid;
            }
          }

          // recursively parse child elements
          for (const key in entry) {
            if (key !== '$' && key !== '_' && Array.isArray(entry[key])) {
              parseXmlList(entry[key], depth + 1);
            }
          }
        }
      };

      // start parsing from device level (depth 0)
      if (descData.device) {
        parseXmlList([descData.device], 0);
      }

      // parse machine description
      const description = {};
      if (descData.device?.description?.[0]) {
        const desc = descData.device.description[0];
        for (const key in desc) {
          if (key !== 'pairableDeviceTypes') {
            description[key] = desc[key][0];
          }
        }
      }

      config.set('description', description);
      config.set('features', features);
    }
  } catch (error) {
    console.error('Could not load or extend config:', error.message);
    mainWindow.webContents.send('app-log', `Could not load or extend config: ${error.message}`);
    throw error;
  }
}

async function fetchApplianceInformationAndWriteProfile(urlPrefix, accessToken, profile, target) {
  try {
    const folderPath = getDownloadDirectory();
    const now = new Date();
    const type = profile.type
      .replace(/([a-z])([A-Z])/g, '$1-$2')
      .toLowerCase();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}-${String(now.getMinutes()).padStart(2, '0')}-${String(now.getSeconds()).padStart(2, '0')}`;
    const brand = profile.brand.toLowerCase();
    const vib = profile.vib.toLowerCase();
    const mac = profile.mac.replace(/-/g, '').toLowerCase();
    const filePrefix = target === 'homeconnectdirect' ? 'homeconnectdirect' : 'homeconnect-local-hass'

    const zipFilePath = path.join(folderPath,
      `${filePrefix}-${type}-${brand}-${vib}-${mac}_${formattedDate}.zip`);

    const zip = await fetchApplianceInformationZip(urlPrefix, accessToken, profile.haId);
    zip.file(`${profile.haId}.json`, JSON.stringify(profile, null, 2));

    const modifiedZipContent = await zip.generateAsync({ type: 'nodebuffer' });
    fs.writeFileSync(zipFilePath, modifiedZipContent);
    console.log(`Modified ZIP saved: ${zipFilePath}`);

    return zipFilePath;
  } catch (error) {
    console.error('Could not load or write profile zip:', error.message);
    mainWindow.webContents.send('app-log', `Could not load or write profile zip: ${error.message}`);
    throw error;
  }
}

async function writeHcpyConfig(devices) {
  try {
    const folderPath = getDownloadDirectory();
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}-${String(now.getMinutes()).padStart(2, '0')}-${String(now.getSeconds()).padStart(2, '0')}`;
    const filePath = path.join(folderPath, `hcpy-devices_${formattedDate}.json`);

    // convert Maps to Objects
    const devicesArray = devices.map(deviceMap => {
      const deviceObj = {};
      for (const [key, value] of deviceMap) {
        deviceObj[key] = value;
      }
      return deviceObj;
    });

    // write to file
    fs.writeFileSync(filePath, JSON.stringify(devicesArray, null, 2));
    console.log(`hcpy config saved: ${filePath}`);

    return filePath;
  } catch (error) {
    console.error('Could not write hcpy config json:', error.message);
    mainWindow.webContents.send('app-log', `Could not write hcpy config json: ${error.message}`);
    throw error;
  }
}

function getDownloadDirectory() {
  const folderPath = path.join(app.getPath('temp'), "home-connect-profiles");

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`Created target directory: ${folderPath}`);
  }

  return folderPath;
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