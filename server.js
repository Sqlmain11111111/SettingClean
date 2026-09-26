require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const express = require('express');

const app = express();
const port = Number(process.env.PORT || 3000);
const sessions = new Map();
const htmlFile = path.join(__dirname, '19S FiveM HuB.html');
const imageDirectory = path.join(__dirname, 'Img');
const imageExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif']);

const keyAuthConfig = {
  name: process.env.KEYAUTH_NAME,
  ownerid: process.env.KEYAUTH_OWNER_ID,
  ver: process.env.KEYAUTH_VERSION || '1.0',
  apiUrl: process.env.KEYAUTH_API_URL || 'https://keyauth.win/api/1.3/'
};

function normalizeKeyAuthMessage(message) {
  if (typeof message !== 'string') return 'คีย์ไม่ถูกต้องหรือหมดอายุ';

  const trimmed = message.trim();
  if (!trimmed) return 'คีย์ไม่ถูกต้องหรือหมดอายุ';

  if (/ownerid|owner id|app name|appname|name is|validation/i.test(trimmed)) {
    return 'การตั้งค่า KeyAuth ไม่ตรงกับแอปนี้ กรุณาตรวจสอบ NAME / OWNER ID';
  }

  return trimmed;
}

app.use(express.json({limit: '4kb'}));
app.use('/Img', express.static(imageDirectory, {index: false}));

app.get('/api/images', async (request, response) => {
  try {
    const files = await fs.readdir(imageDirectory, {withFileTypes: true});
    const images = files
      .filter((file) => file.isFile() && imageExtensions.has(path.extname(file.name).toLowerCase()))
      .map((file) => `/Img/${encodeURIComponent(file.name)}`);
    return response.json({images});
  } catch (error) {
    console.error('Image folder read failed:', error.message);
    return response.status(500).json({images: []});
  }
});

async function keyAuthRequest(params) {
  const response = await fetch(keyAuthConfig.apiUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(params)
  });

  if (!response.ok) {
    throw new Error(`KeyAuth HTTP ${response.status}`);
  }
  return response.json();
}

async function validateKey(key, hwid) {
  const init = await keyAuthRequest({
    type: 'init',
    name: keyAuthConfig.name,
    ownerid: keyAuthConfig.ownerid,
    ver: keyAuthConfig.ver
  });

  if (!init.success) {
    throw new Error(normalizeKeyAuthMessage(init.message || 'KeyAuth initialization failed'));
  }

  const license = await keyAuthRequest({
    type: 'license',
    key,
    hwid,
    name: keyAuthConfig.name,
    ownerid: keyAuthConfig.ownerid,
    ver: keyAuthConfig.ver,
    sessionid: init.sessionid
  });

  if (!license.success) {
    throw new Error(normalizeKeyAuthMessage(license.message || 'Invalid or expired key'));
  }

  return {
    keyAuthSession: init.sessionid,
    username: license.info && license.info.username
  };
}

function getSession(request) {
  const cookies = request.headers.cookie || '';
  const match = cookies.match(/(?:^|; )sui_session=([^;]+)/);
  if (!match) return null;

  const session = sessions.get(match[1]);
  if (!session || session.expiresAt < Date.now()) {
    if (match[1]) sessions.delete(match[1]);
    return null;
  }
  return session;
}

app.post('/api/login', async (request, response) => {
  const key = typeof request.body.key === 'string' ? request.body.key.trim() : '';
  const hwid = typeof request.body.hwid === 'string' ? request.body.hwid.trim() : '';
  if (!key || key.length > 200 || !hwid || hwid.length > 200) {
    return response.status(400).json({success: false, message: 'กรุณาใส่คีย์ให้ถูกต้อง'});
  }

  try {
    const account = await validateKey(key, hwid);
    const sessionToken = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionToken, {
      keyAuthSession: account.keyAuthSession,
      username: account.username || null,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    });

    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    response.setHeader('Set-Cookie', `sui_session=${sessionToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`);
    return response.json({success: true, username: account.username || null});
  } catch (error) {
    const message = error && error.message ? error.message : 'คีย์ไม่ถูกต้องหรือหมดอายุ';
    console.error('KeyAuth login failed:', message);

    if (message.includes('KeyAuth HTTP')) {
      return response.status(401).json({success: false, message: 'ไม่สามารถเชื่อมต่อ KeyAuth ได้'});
    }

    return response.status(401).json({success: false, message});
  }
});

app.get('/api/session', (request, response) => {
  const session = getSession(request);
  if (!session) return response.status(401).json({authenticated: false});
  return response.json({authenticated: true, username: session.username});
});

app.post('/api/logout', (request, response) => {
  const cookies = request.headers.cookie || '';
  const match = cookies.match(/(?:^|; )sui_session=([^;]+)/);
  if (match) sessions.delete(match[1]);
  response.setHeader('Set-Cookie', 'sui_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  return response.json({success: true});
});

app.get('/', (request, response) => response.sendFile(htmlFile));

if (require.main === module) {
  app.listen(port, () => console.log(`SUIJ web server running at http://localhost:${port}`));
}

module.exports = {
  normalizeKeyAuthMessage,
  app
};
