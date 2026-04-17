// ============================================================
//  Echo Messenger – server.js  v5.0
//  npm install ws express express-session passport passport-google-oauth20 dotenv nodemailer
// ============================================================
'use strict';
require('dotenv').config();
const express   = require('express');
const session   = require('express-session');
const passport  = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const http      = require('http');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const { WebSocketServer } = require('ws');

const PORT           = process.env.PORT || 3000;
const GOOGLE_ID      = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET  = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || 'echo-secret-2025';
const BASE_URL       = process.env.BASE_URL || `http://localhost:${PORT}`;
const ADMIN_EMAIL    = 'saschamykkekan@gmail.com';
const DATA_FILE      = path.join(__dirname, 'data.json');

// ── Nodemailer setup ──────────────────────────────────────────
let mailer = null;
try {
  const nodemailer = require('nodemailer');
  if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
    mailer = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
    });
    mailer.verify(err => {
      if (err) { console.warn('⚠️  Email не налаштовано:', err.message); mailer=null; }
      else console.log('✅ Email готовий: '+process.env.GMAIL_USER);
    });
  } else {
    console.warn('⚠️  GMAIL_USER / GMAIL_PASS не задані — email вимкнено');
  }
} catch(e) { console.warn('⚠️  nodemailer не встановлено. Запусти: npm install nodemailer'); }

async function sendMail(to, subject, html) {
  if (!mailer) return false;
  if (!to || to.endsWith('@local')) return false; // skip local users
  try {
    await mailer.sendMail({
      from: `"Echo Messenger" <${process.env.GMAIL_USER}>`,
      to, subject, html,
    });
    return true;
  } catch(e) { console.error('Email error:', e.message); return false; }
}

// Email templates
function emailVerifyTpl(code) {
  return `
  <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0d0f18;color:#eceef5;border-radius:16px;overflow:hidden">
    <div style="background:linear-gradient(135deg,#5b6ef5,#38e2b0);padding:28px;text-align:center">
      <div style="font-size:40px">💬</div>
      <div style="font-size:26px;font-weight:800;letter-spacing:-1px;color:#fff;margin-top:8px">Echo</div>
    </div>
    <div style="padding:28px">
      <h2 style="margin:0 0 12px;font-size:20px">Підтвердження email</h2>
      <p style="color:#7a82a0;font-size:14px;margin-bottom:24px">Введи цей код в Echo для підтвердження акаунту:</p>
      <div style="background:#232840;border-radius:14px;padding:20px;text-align:center;letter-spacing:10px;font-size:36px;font-weight:800;color:#5b6ef5;font-family:monospace">${code}</div>
      <p style="color:#7a82a0;font-size:12px;margin-top:16px">Код дійсний 10 хвилин. Якщо ти не реєструвався — проігноруй.</p>
    </div>
  </div>`;
}

function emailLoginAlertTpl({name, country, city, device, ip, time}) {
  return `
  <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0d0f18;color:#eceef5;border-radius:16px;overflow:hidden">
    <div style="background:linear-gradient(135deg,#f05566,#e040fb);padding:28px;text-align:center">
      <div style="font-size:40px">🔐</div>
      <div style="font-size:26px;font-weight:800;color:#fff;margin-top:8px">Новий вхід</div>
    </div>
    <div style="padding:28px">
      <h2 style="margin:0 0 8px;font-size:18px">Привіт, ${name}!</h2>
      <p style="color:#7a82a0;font-size:14px;margin-bottom:20px">Хтось увійшов у твій акаунт Echo з нового пристрою.</p>
      <div style="background:#232840;border-radius:12px;padding:16px;display:grid;gap:10px">
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#7a82a0">📍 Місто</span><span style="font-weight:600">${city||'Невідомо'}, ${country||'Невідомо'}</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#7a82a0">📱 Пристрій</span><span style="font-weight:600">${device||'Невідомо'}</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#7a82a0">🌐 IP</span><span style="font-weight:600">${ip||'Невідомо'}</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#7a82a0">🕐 Час</span><span style="font-weight:600">${time}</span></div>
      </div>
      <p style="color:#f05566;font-size:13px;margin-top:16px;background:rgba(240,85,102,.1);border-radius:8px;padding:10px">⚠️ Якщо це не ти — негайно змін пароль!</p>
    </div>
  </div>`;
}

// ── Pending verifications ─────────────────────────────────────
// code -> {email, name, userId, expires, type: 'register'|'login', loginData}
const pendingCodes = new Map();

// ── Data load ─────────────────────────────────────────────────
function loadData() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch(e) { console.error('data.json error:', e.message); }
  return {};
}
const D = loadData();

// ── State ─────────────────────────────────────────────────────
const banned      = new Set(D.banned      || []);
const admins      = new Set(D.admins      || []);
const verifiedSet = new Set(D.verifiedSet || []);
const vipSet      = new Set(D.vipSet      || []);
const coins       = new Map(Object.entries(D.coins      || {}));
const privileges  = new Map(Object.entries(D.privileges || {}));
const profiles    = new Map(Object.entries(D.profiles   || {}));
const usernameIdx = new Map();
const localUsers  = D.localUsers || {};
const vipPrefs    = new Map(Object.entries(D.vipPrefs   || {}));
const adminLog    = D.adminLog  || [];
const polls       = new Map();
const stories     = [];
const pinnedMsgs  = new Map();
let groupSeq    = D.groupSeq    || 1;
let channelSeq  = D.channelSeq  || 1;
let pollSeq     = 1;

const groups = new Map(
  Object.entries(D.groups || {}).map(([id,g]) => [id, {...g, members: new Set(g.members||[])}])
);
const channels = new Map(
  Object.entries(D.channels || {}).map(([id,c]) => [id, {
    ...c,
    subscribers: new Set(c.subscribers||[]),
    admins:      new Set(c.admins||[]),
    posts:       c.posts || [],
  }])
);
const channelChats = new Map(Object.entries(D.channelChats || {}));

// Rebuild username index
for (const [uid, p] of profiles) {
  if (p.username) usernameIdx.set(p.username.toLowerCase(), uid);
}

// ── Save ──────────────────────────────────────────────────────
function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify({
      banned:      [...banned],
      admins:      [...admins],
      verifiedSet: [...verifiedSet],
      vipSet:      [...vipSet],
      coins:       Object.fromEntries(coins),
      privileges:  Object.fromEntries(privileges),
      profiles:    Object.fromEntries(profiles),
      localUsers,
      groupSeq, channelSeq,
      groups:   Object.fromEntries([...groups.entries()].map(([id,g]) => [id, {...g, members:[...g.members]}])),
      channels: Object.fromEntries([...channels.entries()].map(([id,c]) => [id, {
        ...c, subscribers:[...c.subscribers], admins:[...c.admins],
      }])),
      channelChats: Object.fromEntries(channelChats),
      vipPrefs:    Object.fromEntries(vipPrefs),
      adminLog:    adminLog.slice(-500),
    }, null, 2));
  } catch(e) { console.error('save error:', e.message); }
}
setInterval(saveData, 30000);

// ── Helpers ───────────────────────────────────────────────────
const getCoins   = uid => coins.get(uid) || 0;
const addCoins   = (uid, n) => { coins.set(uid, getCoins(uid) + n); };
const isVip      = uid => vipSet.has(uid);
const isAdmin    = uid => admins.has(uid);
const getPriv    = uid => privileges.get(uid) || 'member';
const getProfile = uid => profiles.get(uid) || {};
const PRIV_RANK  = {member:0,moder:1,moder_senior:2,admin_junior:3,admin:4,creator:5};
const hasPriv    = (uid,min) => (PRIV_RANK[getPriv(uid)]||0) >= (PRIV_RANK[min]||0);
const logAdmin   = (actor,action,target) => adminLog.push({time:Date.now(),actor,action,target});

// VIP daily bonus
setInterval(() => {
  for (const uid of vipSet) {
    addCoins(uid, 5);
    sendTo(uid, {type:'coins_update', coins:getCoins(uid)});
    sendTo(uid, {type:'toast', msg:'👑 +5 ✈️ VIP щоденний бонус!'});
  }
  saveData();
}, 24*60*60*1000);

// ── Echo Bot ─────────────────────────────────────────────────
const ECHO_BOT = {id:'echobot', name:'ECHO BOT OFFICIAL', username:'echobot', avatar:'', verified:true, isBot:true};
function handleBotCommand(text, chatKey, fromUser) {
  if (!text || !text.startsWith('/')) return null;
  const parts = text.trim().split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const arg = (parts[1]||'').replace(/^@/,'').toLowerCase();
  const canMod = isAdmin(fromUser.id) || hasPriv(fromUser.id,'moder');
  switch(cmd) {
    case '/ban': {
      if (!canMod) return '❌ Немає прав.';
      const uid = usernameIdx.get(arg);
      if (!uid) return `❌ @${arg} не знайдений.`;
      banned.add(uid); saveData(); logAdmin(fromUser.id,'ban',arg);
      sendTo(uid, {type:'banned', reason:'Заблокований модератором.'});
      return `🚫 @${arg} заблокований.`;
    }
    case '/unban': {
      if (!canMod) return '❌ Немає прав.';
      const uid2 = usernameIdx.get(arg);
      if (!uid2) return `❌ @${arg} не знайдений.`;
      banned.delete(uid2); saveData(); logAdmin(fromUser.id,'unban',arg);
      return `✅ @${arg} розблокований.`;
    }
    case '/unbanall': {
      if (!canMod) return '❌ Немає прав.';
      const n = banned.size; banned.clear(); saveData(); logAdmin(fromUser.id,'unbanall',`${n}`);
      return `✅ Розблоковано ${n} користувачів.`;
    }
    case '/help': return `🤖 *ECHO BOT OFFICIAL*\n/ban @нік\n/unban @нік\n/unbanall\n/coins @нік\n/help`;
    case '/coins': {
      const uid3 = usernameIdx.get(arg);
      return uid3 ? `✈️ @${arg}: ${getCoins(uid3)} Самолетиків` : `❌ @${arg} не знайдений.`;
    }
    default: return null;
  }
}

// ── Passport ─────────────────────────────────────────────────
if (GOOGLE_ID && GOOGLE_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_ID, clientSecret: GOOGLE_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`,
  }, (_a, _r, profile, done) => {
    const uid = profile.id;
    const user = {
      id: uid,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || '',
      avatar: profile.photos?.[0]?.value || '',
    };
    if (user.email === ADMIN_EMAIL) {
      admins.add(uid); privileges.set(uid, 'creator'); saveData();
    }
    if (!coins.has(uid)) { coins.set(uid, 50); saveData(); }
    user.needsSetup = !getProfile(uid).username;
    done(null, user);
  }));
}
passport.serializeUser((u,done) => done(null,u));
passport.deserializeUser((u,done) => done(null,u));

// ── Express ───────────────────────────────────────────────────
const app = express();
app.use(express.json({limit:'30mb'}));
app.use(session({
  secret:SESSION_SECRET, resave:false, saveUninitialized:false,
  cookie:{maxAge:7*24*60*60*1000},
}));
app.use(passport.initialize());
app.use(passport.session());
app.use((req,res,next)=>{res.setHeader('ngrok-skip-browser-warning','1');next();});

// Static
app.get('/',        (req,res) => res.sendFile(path.join(__dirname,'index.html')));
app.get('/sw.js',   (req,res) => { res.setHeader('Content-Type','application/javascript'); res.setHeader('Service-Worker-Allowed','/'); res.sendFile(path.join(__dirname,'sw.js')); });
app.get('/icon.svg',(req,res) => { res.setHeader('Content-Type','image/svg+xml'); res.sendFile(path.join(__dirname,'icon.svg')); });
app.get('/icon.png',(req,res) => { res.setHeader('Content-Type','image/svg+xml'); res.sendFile(path.join(__dirname,'icon.svg')); });
app.get('/manifest.json',(req,res) => res.json({
  name:'Echo', short_name:'Echo', description:'Echo — твій месенджер',
  start_url:'/', display:'standalone', background_color:'#0d0f18', theme_color:'#4f8fff',
  icons:[{src:'/icon.svg',sizes:'512x512',type:'image/svg+xml'}],
}));

// ── Device/location detection ────────────────────────────────
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  let device = 'Невідомий пристрій';
  if (/iPhone/.test(ua)) device = 'iPhone';
  else if (/iPad/.test(ua)) device = 'iPad';
  else if (/Android/.test(ua)) device = 'Android';
  else if (/Windows/.test(ua)) device = 'Windows PC';
  else if (/Mac/.test(ua)) device = 'Mac';
  else if (/Linux/.test(ua)) device = 'Linux';
  return device;
}

function getIp(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() ||
    req.socket?.remoteAddress || 'Невідомо';
}

async function getGeoInfo(ip) {
  // Use free ip-api.com
  try {
    if (ip === '::1' || ip.startsWith('127.') || ip.startsWith('192.168')) {
      return {country:'Локальна мережа', city:'localhost'};
    }
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,status`);
    const d = await r.json();
    if (d.status === 'success') return {country:d.country||'', city:d.city||''};
  } catch{}
  return {country:'Невідомо', city:'Невідомо'};
}

function makeCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Track known devices per user: userId -> Set<fingerprint>
const knownDevices = new Map();
function getDeviceFingerprint(req) {
  const ua = req.headers['user-agent']||'';
  const lang = req.headers['accept-language']||'';
  return crypto.createHash('sha256').update(ua+lang).digest('hex').slice(0,16);
}
function isKnownDevice(userId, req) {
  const fp = getDeviceFingerprint(req);
  if (!knownDevices.has(userId)) { knownDevices.set(userId, new Set()); }
  return knownDevices.get(userId).has(fp);
}
function markDeviceKnown(userId, req) {
  if (!knownDevices.has(userId)) knownDevices.set(userId, new Set());
  knownDevices.get(userId).add(getDeviceFingerprint(req));
}

// ── Auth ──────────────────────────────────────────────────────
app.get('/auth/google', passport.authenticate('google',{scope:['profile','email']}));
app.get('/auth/google/callback',
  passport.authenticate('google',{failureRedirect:'/?error=auth'}),
  async (req,res) => {
    const u = req.user;
    const isNew = !getProfile(u.id)?.username;
    // Send new-device email if known email and new device
    if (!isNew && u.email && !u.email.endsWith('@local')) {
      if (!isKnownDevice(u.id, req)) {
        const ip = getIp(req);
        const geo = await getGeoInfo(ip);
        const device = getDeviceInfo(req);
        const time = new Date().toLocaleString('uk-UA',{timeZone:'Europe/Kyiv'});
        sendMail(u.email, '🔐 Новий вхід в Echo', emailLoginAlertTpl({
          name: getProfile(u.id)?.displayName || u.name,
          country: geo.country, city: geo.city,
          device, ip, time,
        }));
        markDeviceKnown(u.id, req);
      } else {
        markDeviceKnown(u.id, req);
      }
    } else {
      markDeviceKnown(u.id, req);
    }
    res.redirect(isNew ? '/?setup=1' : '/');
  }
);
app.get('/auth/logout', (req,res) => req.session.destroy(() => res.redirect('/')));

// ── Local auth (nickname + password) ─────────────────────────
app.post('/api/auth/local', async (req,res) => {
  const {nickname, password, email} = req.body;
  const name = (nickname||'').trim().slice(0,32);
  const pass = (password||'').trim();
  const userEmail = (email||'').trim().toLowerCase();
  if (name.length < 2) return res.status(400).json({error:'Нік мін. 2 символи'});
  if (pass.length < 3) return res.status(400).json({error:'Пароль мін. 3 символи'});
  const key = name.toLowerCase();

  if (localUsers[key]) {
    // ── Login ──
    const {salt,hash,id,email:storedEmail} = localUsers[key];
    const h = crypto.pbkdf2Sync(pass,salt,1000,32,'sha256').toString('hex');
    if (h !== hash) return res.status(401).json({error:'Невірний пароль'});
    if (!coins.has(id)) { coins.set(id,50); saveData(); }
    const p = getProfile(id);
    const u = {id, name:localUsers[key].displayName||name, email:storedEmail||key+'@local', avatar:p.avatar||''};

    // New device check — send alert email
    const realEmail = storedEmail || '';
    if (realEmail && !realEmail.endsWith('@local') && !isKnownDevice(id, req)) {
      const ip = getIp(req);
      const geo = await getGeoInfo(ip);
      const device = getDeviceInfo(req);
      const time = new Date().toLocaleString('uk-UA',{timeZone:'Europe/Kyiv'});
      sendMail(realEmail, '🔐 Новий вхід в Echo', emailLoginAlertTpl({
        name: p.displayName || name, country: geo.country, city: geo.city,
        device, ip, time,
      }));
    }
    markDeviceKnown(id, req);
    req.session.localUser = u;
    return res.json({ok:true, user:{...u,...p, needsSetup:!p.username, vip:isVip(id), privilege:getPriv(id), isAdmin:isAdmin(id), coins:getCoins(id), verified:verifiedSet.has(id)}});
  }

  // ── Register ──
  // If email provided — send verification code first
  if (userEmail && !userEmail.endsWith('@local') && mailer) {
    const code = makeCode();
    const tempId = 'loc_'+Date.now()+'_'+Math.random().toString(36).slice(2,6);
    // Store pending registration
    pendingCodes.set(code, {
      type: 'register', key, name, pass, email: userEmail,
      tempId, expires: Date.now() + 10*60*1000,
    });
    await sendMail(userEmail, '✅ Підтвердь реєстрацію в Echo', emailVerifyTpl(code));
    return res.json({ok:true, needVerify:true, email: userEmail.replace(/(.{2}).+(@.+)/,'$1***$2')});
  }

  // Register without email (no verification needed)
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pass,salt,1000,32,'sha256').toString('hex');
  const id = 'loc_'+Date.now()+'_'+Math.random().toString(36).slice(2,6);
  localUsers[key] = {id, displayName:name, salt, hash, email:userEmail||''};
  D.localUsers = localUsers;
  coins.set(id,50); saveData();
  const u = {id, name, email:userEmail||key+'@local', avatar:''};
  markDeviceKnown(id, req);
  req.session.localUser = u;
  res.json({ok:true, user:{...u, needsSetup:true, vip:false, privilege:'member', isAdmin:false, coins:50}});
});

// ── Email verification ─────────────────────────────────────────
app.post('/api/auth/verify-email', async (req,res) => {
  const {code} = req.body;
  const pending = pendingCodes.get(code);
  if (!pending) return res.status(400).json({error:'Невірний або прострочений код'});
  if (Date.now() > pending.expires) { pendingCodes.delete(code); return res.status(400).json({error:'Код прострочений. Спробуй ще раз'}); }
  pendingCodes.delete(code);

  if (pending.type === 'register') {
    const {key, name, pass, email, tempId} = pending;
    // Create account
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(pass,salt,1000,32,'sha256').toString('hex');
    const id = tempId;
    localUsers[key] = {id, displayName:name, salt, hash, email};
    D.localUsers = localUsers;
    coins.set(id,50); saveData();
    const u = {id, name, email, avatar:''};
    markDeviceKnown(id, req);
    req.session.localUser = u;
    return res.json({ok:true, user:{...u, needsSetup:true, vip:false, privilege:'member', isAdmin:false, coins:50}});
  }
  res.status(400).json({error:'Невідомий тип верифікації'});
});

// ── Resend code ───────────────────────────────────────────────
app.post('/api/auth/resend-code', async (req,res) => {
  const {email} = req.body;
  // Find pending code for this email
  for (const [code, pending] of pendingCodes) {
    if (pending.email === email) {
      pendingCodes.delete(code);
      break;
    }
  }
  return res.json({ok:true, message:'Відправили новий код якщо email існує'});
});

// /api/me
app.get('/api/me', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).json({error:'not authenticated'});
  const p = getProfile(u.id);
  res.json({...u,...p, isAdmin:isAdmin(u.id), coins:getCoins(u.id), banned:banned.has(u.id),
    vip:isVip(u.id), privilege:getPriv(u.id), needsSetup:!p.username, verified:verifiedSet.has(u.id), vipPrefs:vipPrefs.get(u.id)});
});

// Profile setup
app.post('/api/setup-profile', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).json({error:'not authenticated'});
  const {username,displayName,avatar,bio} = req.body;
  const uname = (username||'').toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,32);
  if (uname.length < 3) return res.status(400).json({error:'Юзернейм мін. 3 символи (a-z, 0-9, _)'});
  const existing = usernameIdx.get(uname);
  if (existing && existing !== u.id) return res.status(400).json({error:'Юзернейм вже зайнятий'});
  const old = getProfile(u.id);
  if (old.username) usernameIdx.delete(old.username.toLowerCase());
  const p = {
    username: uname,
    displayName: (displayName||u.name||uname).slice(0,32),
    avatar: avatar || u.avatar || '',  // save base64 avatar
    bio: (bio||'').slice(0,160),
    createdAt: old.createdAt || Date.now(),
  };
  profiles.set(u.id, p);
  usernameIdx.set(uname, u.id);
  saveData();
  // Update session user so /api/me returns correct data
  if (req.isAuthenticated() && req.user) {
    req.user.avatar = p.avatar;
    req.user.needsSetup = false;
  }
  if (req.session?.localUser) {
    req.session.localUser.avatar = p.avatar;
    req.session.localUser.name = p.displayName;
    req.session.save?.();
  }
  broadcast({type:'profile_updated', userId:u.id, ...p});
  res.json({ok:true, profile:p});
});

// Search
app.get('/api/search', (req,res) => {
  const q = (req.query.q||'').toLowerCase().replace(/^@/,'');
  if (q.length < 2) return res.json({users:[], channels:[]});
  const users=[]; const chans=[];
  for (const [uname,uid] of usernameIdx) {
    if (uname.includes(q)) {
      const p = getProfile(uid);
      users.push({id:uid, username:uname, displayName:p.displayName||uname, avatar:p.avatar||'',
        vip:isVip(uid), verified:verifiedSet.has(uid), privilege:getPriv(uid), online:clients.has(uid)});
    }
    if (users.length >= 20) break;
  }
  for (const [id,c] of channels) {
    if ((c.username||'').includes(q)||(c.name||'').toLowerCase().includes(q)) {
      chans.push({id, name:c.name, username:c.username, avatar:c.avatar, description:c.description,
        subscribers:c.subscribers.size, verified:verifiedSet.has(id)});
    }
    if (chans.length >= 10) break;
  }
  res.json({users, channels:chans});
});

// ── Channels ──────────────────────────────────────────────────
function channelPublic(c, uid) {
  return {
    id:c.id, name:c.name, username:c.username, avatar:c.avatar, description:c.description,
    ownerId:c.ownerId, subscribers:c.subscribers.size, admins:[...c.admins],
    verified:verifiedSet.has(c.id), createdAt:c.createdAt,
    isOwner:uid===c.ownerId, isAdmin:c.admins.has(uid), isSubscribed:c.subscribers.has(uid),
  };
}

app.post('/api/channels/create', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const {name,username,avatar,description} = req.body;
  const uname = (username||'').toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,32);
  if (!name || uname.length < 3) return res.status(400).json({error:'Назва і @юзернейм обов\'язкові (мін 3)'});
  if ([...channels.values()].some(c=>c.username===uname)) return res.status(400).json({error:'Юзернейм каналу вже зайнятий'});
  const id = 'ch_'+(channelSeq++);
  const ch = {
    id, name:name.slice(0,64), username:uname, avatar:avatar||'',
    description:(description||'').slice(0,256), ownerId:u.id,
    posts:[], subscribers:new Set([u.id]), admins:new Set([u.id]),
    createdAt:Date.now(), verified:false, blocked:false,
  };
  channels.set(id,ch); saveData();
  res.json({ok:true, channel:channelPublic(ch,u.id)});
});

app.get('/api/channels/:id', (req,res) => {
  const c = channels.get(req.params.id); if (!c) return res.status(404).end();
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  res.json({...channelPublic(c,u?.id), posts:c.posts.slice(0,50)});
});

app.post('/api/channels/:id/subscribe', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const c = channels.get(req.params.id); if (!c) return res.status(404).end();
  if (req.body.unsub) c.subscribers.delete(u.id); else c.subscribers.add(u.id);
  saveData(); res.json({ok:true, isSubscribed:c.subscribers.has(u.id), subscribers:c.subscribers.size});
});

app.post('/api/channels/:id/post', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const c = channels.get(req.params.id); if (!c) return res.status(404).end();
  const canPost = c.ownerId===u.id || c.admins.has(u.id) || isAdmin(u.id);
  if (!canPost) return res.status(403).json({error:'Тільки власник і адміни можуть постити'});
  const p = getProfile(u.id);
  const post = {
    id:'p_'+Date.now()+'_'+Math.random().toString(36).slice(2,5),
    text:(req.body.text||'').slice(0,4096),
    fileData:req.body.fileData||null, fileName:req.body.fileName||null, fileType:req.body.fileType||null,
    audio:req.body.audio||null,
    authorId:u.id, authorName:p.displayName||u.name,
    time:Date.now(), likes:[], commentCount:0,
  };
  c.posts.unshift(post); if(c.posts.length>500) c.posts.pop();
  saveData();
  for (const sub of c.subscribers) sendTo(sub, {type:'channel_post', channelId:c.id, channelName:c.name, channelUsername:c.username, post});
  res.json({ok:true, post});
});

app.post('/api/channels/:id/posts/:pid/like', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const c = channels.get(req.params.id);
  const post = c?.posts.find(p=>p.id===req.params.pid); if (!post) return res.status(404).end();
  if (!Array.isArray(post.likes)) post.likes=[];
  const i = post.likes.indexOf(u.id);
  if (i>=0) post.likes.splice(i,1); else post.likes.push(u.id);
  saveData(); broadcast({type:'post_liked', channelId:c.id, postId:post.id, likes:post.likes.length});
  res.json({ok:true, likes:post.likes.length, liked:post.likes.includes(u.id)});
});

app.delete('/api/channels/:id/posts/:pid', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const c = channels.get(req.params.id); if (!c) return res.status(404).end();
  if (c.ownerId!==u.id && !c.admins.has(u.id) && !isAdmin(u.id)) return res.status(403).end();
  c.posts = c.posts.filter(p=>p.id!==req.params.pid); saveData();
  broadcast({type:'post_deleted', channelId:c.id, postId:req.params.pid});
  res.json({ok:true});
});

// Channel chat (post discussion)
app.get('/api/channels/:id/chat/:postId', (req,res) => {
  const key = req.params.id+':'+req.params.postId;
  res.json(channelChats.get(key)||[]);
});
app.post('/api/channels/:id/chat/:postId', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  const c = channels.get(req.params.id);
  if (!c||!c.subscribers.has(u.id)) return res.status(403).json({error:'Підпишись на канал'});
  const key = req.params.id+':'+req.params.postId;
  const p = getProfile(u.id);
  const msg = {id:'m_'+Date.now(), from:{id:u.id, name:p.displayName||u.name, avatar:p.avatar||''}, text:(req.body.text||'').slice(0,2000), time:Date.now()};
  if (!channelChats.has(key)) channelChats.set(key,[]);
  const arr = channelChats.get(key);
  arr.push(msg); if(arr.length>200) arr.shift();
  const post = c.posts.find(p2=>p2.id===req.params.postId);
  if (post) post.commentCount = arr.length;
  saveData();
  for (const sub of c.subscribers) sendTo(sub, {type:'channel_chat_msg', channelId:c.id, postId:req.params.postId, msg});
  res.json({ok:true, msg});
});

app.get('/api/my-channels', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u) return res.status(401).end();
  res.json([...channels.values()].filter(c=>c.subscribers.has(u.id)||c.ownerId===u.id).map(c=>channelPublic(c,u.id)));
});

// ── Admin ─────────────────────────────────────────────────────
// Easter egg hunt reward
app.post('/api/event/egg-hunt-complete',(req,res)=>{
  const u=req.user||req.session?.localUser;if(!u)return res.status(401).end();
  addCoins(u.id,50);
  sendTo(u.id,{type:'coins_update',coins:getCoins(u.id)});
  res.json({ok:true,coins:getCoins(u.id)});
});

function requireAdmin(req,res,next){
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u||!isAdmin(u.id)) return res.status(403).json({error:'Forbidden'});
  req.me = u; next();
}
app.get('/api/admin/users', requireAdmin, (req,res) => {
  res.json([...clients.values()].map(c=>({
    id:c.user.id, name:c.user.name, ...getProfile(c.user.id),
    coins:getCoins(c.user.id), banned:banned.has(c.user.id),
    isAdmin:isAdmin(c.user.id), vip:isVip(c.user.id), privilege:getPriv(c.user.id), verified:verifiedSet.has(c.user.id),
  })));
});
app.get('/api/admin/channels', requireAdmin, (req,res) => {
  res.json([...channels.values()].map(c=>({
    id:c.id, name:c.name, username:c.username, ownerId:c.ownerId,
    subscribers:c.subscribers.size, posts:c.posts.length,
    verified:verifiedSet.has(c.id), blocked:c.blocked||false, createdAt:c.createdAt,
  })));
});
app.get('/api/admin/log', requireAdmin, (req,res) => res.json(adminLog.slice(-200)));
app.post('/api/admin/ban',    requireAdmin, (req,res) => { banned.add(req.body.userId); saveData(); logAdmin(req.me.id,'ban',req.body.userId); const c2=clients.get(req.body.userId); if(c2){sendTo(req.body.userId,{type:'banned',reason:'Адмін'});c2.ws.close();} res.json({ok:true}); });
app.post('/api/admin/unban',  requireAdmin, (req,res) => { banned.delete(req.body.userId); saveData(); res.json({ok:true}); });
app.post('/api/admin/give-coins', requireAdmin, (req,res) => { addCoins(req.body.userId,Number(req.body.amount)||0); saveData(); sendTo(req.body.userId,{type:'coins_update',coins:getCoins(req.body.userId)}); res.json({ok:true,coins:getCoins(req.body.userId)}); });
app.post('/api/admin/give-admin', requireAdmin, (req,res) => {
  const {userId} = req.body;
  admins.add(userId); saveData();
  logAdmin(req.me.id,'give_admin',userId);
  sendTo(userId,{type:'admin_granted'});
  res.json({ok:true});
});
// Give creator privilege (only existing creator can do this)
app.post('/api/admin/give-creator', requireAdmin, (req,res) => {
  const {userId} = req.body;
  admins.add(userId);
  privileges.set(userId,'creator');
  saveData();
  logAdmin(req.me.id,'give_creator',userId);
  sendTo(userId,{type:'admin_granted'});
  sendTo(userId,{type:'privilege_update',privilege:'creator'});
  res.json({ok:true});
});
app.post('/api/admin/self-coins', requireAdmin, (req,res) => { const n=Math.min(Number(req.body.amount)||0,999999); addCoins(req.me.id,n); saveData(); sendTo(req.me.id,{type:'coins_update',coins:getCoins(req.me.id)}); res.json({ok:true,coins:getCoins(req.me.id)}); });
app.post('/api/admin/vip',        requireAdmin, (req,res) => { const{userId,revoke}=req.body; if(revoke)vipSet.delete(userId);else vipSet.add(userId); saveData(); logAdmin(req.me.id,revoke?'revoke_vip':'give_vip',userId); sendTo(userId,{type:'vip_update',vip:!revoke}); res.json({ok:true}); });
app.post('/api/admin/privilege',  requireAdmin, (req,res) => { const{userId,level}=req.body; if(!level||level==='member')privileges.delete(userId);else privileges.set(userId,level); saveData(); logAdmin(req.me.id,'privilege',`${userId}=${level}`); sendTo(userId,{type:'privilege_update',privilege:level||'member'}); res.json({ok:true}); });
app.post('/api/admin/verify',     requireAdmin, (req,res) => { const{targetId,revoke}=req.body; if(revoke)verifiedSet.delete(targetId);else verifiedSet.add(targetId); saveData(); logAdmin(req.me.id,revoke?'unverify':'verify',targetId); broadcast({type:'verified_update',targetId,verified:!revoke}); res.json({ok:true}); });
app.post('/api/admin/channel-action', requireAdmin, (req,res) => {
  const{channelId,action}=req.body; const c=channels.get(channelId); if(!c) return res.status(404).end();
  if(action==='delete'){channels.delete(channelId);saveData();broadcast({type:'channel_deleted',channelId});}
  if(action==='block'){c.blocked=true;saveData();broadcast({type:'channel_blocked',channelId});}
  if(action==='unblock'){c.blocked=false;saveData();}
  if(action==='verify'){verifiedSet.add(channelId);saveData();broadcast({type:'verified_update',targetId:channelId,verified:true});}
  if(action==='unverify'){verifiedSet.delete(channelId);saveData();broadcast({type:'verified_update',targetId:channelId,verified:false});}
  logAdmin(req.me.id,action,channelId); res.json({ok:true});
});

// VIP prefs
app.post('/api/vip/prefs', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser;
  if (!u||!isVip(u.id)) return res.status(403).json({error:'VIP тільки'});
  vipPrefs.set(u.id,{bg:req.body.bg||'',rainbow:!!req.body.rainbow}); saveData();
  broadcast({type:'vip_prefs_update',userId:u.id,...vipPrefs.get(u.id)});
  res.json({ok:true});
});

// Leaderboard
app.get('/api/leaderboard', (req,res) => {
  res.json([...clients.values()].map(c=>({id:c.user.id,...getProfile(c.user.id),coins:getCoins(c.user.id),vip:isVip(c.user.id)})).sort((a,b)=>b.coins-a.coins).slice(0,30));
});

// Emoji shop
const EMOJI_CATALOG=[
  {id:'ball_smile',  name:'Усмішка',   grad:'radial-gradient(circle at 35% 35%,#ffe066,#ff9900)',face:'😊',anim:'bounce'},
  {id:'ball_cool',   name:'Крутий',    grad:'radial-gradient(circle at 35% 35%,#66e0ff,#0066ff)',face:'😎',anim:'spin'},
  {id:'ball_love',   name:'Закоханий', grad:'radial-gradient(circle at 35% 35%,#ffb3c6,#ff3366)',face:'😍',anim:'pulse'},
  {id:'ball_fire',   name:'Вогонь',    grad:'radial-gradient(circle at 35% 35%,#ffcc00,#ff4400)',face:'🔥',anim:'shake'},
  {id:'ball_star',   name:'Зірка',     grad:'radial-gradient(circle at 35% 35%,#fff066,#ffaa00)',face:'⭐',anim:'bounce'},
  {id:'ball_ghost',  name:'Привид',    grad:'radial-gradient(circle at 35% 35%,#e8e8e8,#aaaaaa)',face:'👻',anim:'float'},
  {id:'ball_alien',  name:'Прибулець', grad:'radial-gradient(circle at 35% 35%,#aaffaa,#00bb44)',face:'👽',anim:'spin'},
  {id:'ball_devil',  name:'Чортик',    grad:'radial-gradient(circle at 35% 35%,#ff9999,#cc0000)',face:'😈',anim:'shake'},
  {id:'ball_ice',    name:'Крижаний',  grad:'radial-gradient(circle at 35% 35%,#ccffff,#00ccff)',face:'🧊',anim:'float'},
  {id:'ball_rainbow',name:'Веселка',   grad:'linear-gradient(135deg,#f00,#f80,#ff0,#0f0,#00f,#80f)',face:'🌈',anim:'pulse'},
];
app.get('/api/shop', (req,res) => res.json(EMOJI_CATALOG));
app.post('/api/buy-emoji', (req,res) => {
  const u = req.isAuthenticated() ? req.user : req.session?.localUser; if(!u) return res.status(401).end();
  const item = EMOJI_CATALOG.find(e=>e.id===req.body.id); if(!item) return res.status(404).end();
  if(getCoins(u.id)<100) return res.status(400).json({error:'Не вистачає монет'});
  addCoins(u.id,-100); saveData(); sendTo(u.id,{type:'coins_update',coins:getCoins(u.id)});
  res.json({ok:true,coins:getCoins(u.id),item});
});

// Cases
const CASES=[{id:'spring',name:'Весняний кейс',icon:'🌸',price:1000,grad:'linear-gradient(135deg,#ff9de2,#b9a0ff)',description:'Рідкісний весняний набір'}];
app.get('/api/cases',(req,res)=>res.json(CASES));
app.post('/api/open-case',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const c2=CASES.find(c=>c.id===req.body.caseId); if(!c2)return res.status(404).end();
  if(getCoins(u.id)<c2.price)return res.status(400).json({error:`Потрібно ${c2.price} ✈️`});
  addCoins(u.id,-c2.price); saveData();
  res.json({ok:true,coins:getCoins(u.id),item:EMOJI_CATALOG[Math.floor(Math.random()*EMOJI_CATALOG.length)]});
});

// Polls
app.post('/api/polls',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const{question,options,chatKey}=req.body;
  if(!question||!options||options.length<2)return res.status(400).json({error:'Invalid'});
  const id='poll_'+(pollSeq++);
  const poll={id,question:question.slice(0,200),options:options.slice(0,10).map(o=>({text:o.slice(0,100),voters:[]})),chatKey,createdBy:u.id,time:Date.now()};
  polls.set(id,poll); res.json({ok:true,poll});
});
app.post('/api/polls/:id/vote',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const poll=polls.get(req.params.id); if(!poll)return res.status(404).end();
  poll.options.forEach(o=>{const i=o.voters.indexOf(u.id);if(i>=0)o.voters.splice(i,1);});
  if(poll.options[req.body.optionIdx])poll.options[req.body.optionIdx].voters.push(u.id);
  broadcast({type:'poll_update',poll}); res.json({ok:true,poll});
});

// Stories
app.post('/api/stories',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const p=getProfile(u.id);
  const story={id:'s_'+Date.now(),userId:u.id,userName:p.displayName||u.name,avatar:p.avatar||'',text:(req.body.text||'').slice(0,200),img:req.body.img||null,time:Date.now(),viewers:[]};
  stories.push(story); broadcast({type:'new_story',story:{...story,img:undefined,hasImg:!!story.img}});
  res.json({ok:true,id:story.id});
});
app.get('/api/stories',(req,res)=>{
  const now=Date.now(); const fresh=stories.filter(s=>now-s.time<24*3600*1000);
  res.json(fresh.map(s=>({...s,img:undefined,hasImg:!!s.img})));
});
app.get('/api/stories/:id/img',(req,res)=>{
  const s=stories.find(x=>x.id===req.params.id); if(!s||!s.img)return res.status(404).end();
  res.set('Content-Type','image/jpeg').send(Buffer.from(s.img.split(',')[1]||'','base64'));
});

// Pin / Gift / Block
app.post('/api/pin',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const{chatKey,text,from,time}=req.body; pinnedMsgs.set(chatKey,{text,from,time,pinnedBy:u.name});
  broadcast({type:'msg_pinned',chatKey,pinned:pinnedMsgs.get(chatKey)}); res.json({ok:true});
});
app.get('/api/pin/:key',(req,res)=>res.json(pinnedMsgs.get(decodeURIComponent(req.params.key))||null));
app.post('/api/gift',(req,res)=>{
  const u=req.isAuthenticated()?req.user:req.session?.localUser; if(!u)return res.status(401).end();
  const{toUserId,amount}=req.body; const amt=Math.min(Number(amount)||0,getCoins(u.id));
  if(amt<1)return res.status(400).json({error:'Не вистачає монет'});
  addCoins(u.id,-amt); addCoins(toUserId,amt); saveData();
  sendTo(u.id,{type:'coins_update',coins:getCoins(u.id)});
  sendTo(toUserId,{type:'gift_received',from:{id:u.id,name:getProfile(u.id).displayName||u.name},amount:amt,coins:getCoins(toUserId)});
  res.json({ok:true});
});

// ── WebSocket ─────────────────────────────────────────────────
const httpServer = http.createServer(app);
const wss = new WebSocketServer({server:httpServer, path:'/ws'});
const clients = new Map();

function sendTo(uid,data){const c=clients.get(uid);if(c&&c.ws.readyState===1)c.ws.send(JSON.stringify(data));}
function broadcast(data,exceptId){const s=JSON.stringify(data);for(const[uid,c]of clients)if(uid!==exceptId&&c.ws.readyState===1)c.ws.send(s);}
function broadcastToGroup(gid,data,exceptId){const g=groups.get(gid);if(!g)return;for(const uid of g.members)if(uid!==exceptId)sendTo(uid,data);}
function getOnline(){
  return [...clients.values()].map(c=>{
    const p=getProfile(c.user.id);
    return{...c.user,...p,coins:getCoins(c.user.id),isAdmin:isAdmin(c.user.id),vip:isVip(c.user.id),privilege:getPriv(c.user.id),verified:verifiedSet.has(c.user.id)};
  });
}
function groupPublic(g){return{...g,members:[...g.members]};}

wss.on('connection', ws => {
  let userId=null;
  ws.on('message', raw => {
    let msg; try{msg=JSON.parse(raw);}catch{return;}
    if(msg.type==='auth'){
      const u=msg.user; if(!u||banned.has(u.id)){ws.send(JSON.stringify({type:'banned',reason:'Заблокований'}));ws.close();return;}
      userId=u.id;
      const p=getProfile(u.id);
      const enriched={...u,...p,vip:isVip(u.id),privilege:getPriv(u.id),verified:verifiedSet.has(u.id),isAdmin:isAdmin(u.id),vipPrefs:vipPrefs.get(u.id)};
      clients.set(userId,{ws,user:enriched});
      sendTo(userId,{type:'joined',user:enriched,online:getOnline(),coins:getCoins(userId),isAdmin:isAdmin(userId),
        groups:[...groups.values()].filter(g=>g.members.has(userId)).map(groupPublic),
        vip:isVip(userId),privilege:getPriv(userId),vipPrefs:vipPrefs.get(userId)});
      broadcast({type:'user_joined',user:enriched,online:getOnline()},userId);
      return;
    }
    if(!userId)return;
    const from=clients.get(userId)?.user; if(!from)return;

    switch(msg.type){
      case 'chat':{
        if(banned.has(userId))return;
        const text=(msg.text||'').slice(0,4096);
        const pkt={type:'chat',from,text,time:Date.now()};
        broadcast(pkt,null);
        const botReply=handleBotCommand(text,'__all__',from);
        if(botReply)setTimeout(()=>broadcast({type:'chat',from:ECHO_BOT,text:botReply,time:Date.now()}),600);
        break;
      }
      case 'pm':{
        if(banned.has(userId))return;
        const text2=(msg.text||'').slice(0,4096);
        const pkt2={type:'pm',from,to:msg.to,text:text2,time:Date.now()};
        sendTo(msg.to,pkt2);sendTo(userId,pkt2);
        const botReply2=handleBotCommand(text2,msg.to,from);
        if(botReply2){
          const bp={type:'pm',from:ECHO_BOT,to:userId,text:botReply2,time:Date.now()};
          setTimeout(()=>{sendTo(userId,bp);sendTo(msg.to,{...bp,to:msg.to});},600);
        }
        break;
      }
      case 'voice_msg':case 'file_msg':case 'emoji_msg':case 'circle_msg':{
        if(banned.has(userId))return;
        const pkt3={...msg,from,time:Date.now()};
        if(msg.groupId)broadcastToGroup(msg.groupId,pkt3);
        else if(msg.to==='__all__')broadcast(pkt3,null);
        else{sendTo(msg.to,pkt3);sendTo(userId,pkt3);}
        break;
      }
      case 'group_msg':case 'group_voice':{
        if(banned.has(userId))return;
        const g=groups.get(msg.groupId); if(!g||!g.members.has(userId))return;
        broadcastToGroup(msg.groupId,{...msg,from,time:Date.now()});
        break;
      }
      case 'create_group':{
        const id='grp_'+(groupSeq++);
        const g={id,name:(msg.name||'Група').slice(0,64),members:new Set([userId,...(msg.members||[])]),owner:userId,createdAt:Date.now()};
        groups.set(id,g);saveData();
        for(const uid of g.members)sendTo(uid,{type:'group_created',group:groupPublic(g)});
        break;
      }
      case 'add_to_group':{const g2=groups.get(msg.groupId);if(!g2||g2.owner!==userId)return;g2.members.add(msg.userId);saveData();for(const uid of g2.members)sendTo(uid,{type:'group_updated',group:groupPublic(g2)});break;}
      case 'leave_group':{const g3=groups.get(msg.groupId);if(!g3)return;g3.members.delete(userId);saveData();sendTo(userId,{type:'group_left',groupId:msg.groupId});broadcastToGroup(msg.groupId,{type:'group_updated',group:groupPublic(g3)});break;}
      case 'call_request': sendTo(msg.to,{type:'call_request',from});break;
      case 'call_answer':  sendTo(msg.to,{type:'call_answer',from,accepted:msg.accepted});break;
      case 'call_end':     sendTo(msg.to,{type:'call_end',from});break;
      case 'offer':        sendTo(msg.to,{type:'offer',from,sdp:msg.sdp});break;
      case 'answer':       sendTo(msg.to,{type:'answer',from,sdp:msg.sdp});break;
      case 'ice':          sendTo(msg.to,{type:'ice',from,candidate:msg.candidate});break;
      case 'cam_offer':    sendTo(msg.to,{type:'cam_offer',from,sdp:msg.sdp});break;
      case 'cam_answer':   sendTo(msg.to,{type:'cam_answer',from,sdp:msg.sdp});break;
      case 'group_call_join':  broadcastToGroup(msg.groupId,{type:'group_call_join',from,groupId:msg.groupId},userId);break;
      case 'group_call_leave': broadcastToGroup(msg.groupId,{type:'group_call_leave',from,groupId:msg.groupId},userId);break;
      case 'group_offer':  sendTo(msg.to,{type:'group_offer',from,sdp:msg.sdp,callId:msg.callId,groupId:msg.groupId});break;
      case 'group_answer': sendTo(msg.to,{type:'group_answer',from,sdp:msg.sdp,callId:msg.callId});break;
      case 'group_ice':    sendTo(msg.to,{type:'group_ice',from,candidate:msg.candidate,callId:msg.callId});break;
      case 'rc_started':case 'rc_stopped':case 'rc_mouse':case 'rc_key': sendTo(msg.to,{...msg,from});break;
      case 'typing':       sendTo(msg.to,{type:'typing',from});break;
      case 'reaction':{
        const rpkt={type:'reaction',from,msgKey:msg.msgKey,emoji:msg.emoji};
        if(msg.to==='__all__')broadcast(rpkt,null);else{sendTo(msg.to,rpkt);sendTo(userId,rpkt);}
        break;
      }
      case 'delete_msg':case 'edit_msg':{
        const epkt={...msg,from};
        if(msg.chatKey==='__all__')broadcast(epkt,null);
        else if(msg.chatKey?.startsWith('grp_'))broadcastToGroup(msg.chatKey,epkt);
        else{sendTo(msg.chatKey,epkt);sendTo(userId,epkt);}
        break;
      }
      case 'daily_bonus': addCoins(userId,10);saveData();sendTo(userId,{type:'daily_bonus',coins:getCoins(userId)});break;
      case 'set_status':  broadcast({type:'status_update',userId,status:msg.status,text:msg.text||''},null);break;
      case 'gift':{
        const amt2=Math.min(Number(msg.amount)||0,getCoins(userId)); if(amt2<1)return;
        addCoins(userId,-amt2);addCoins(msg.toUserId,amt2);saveData();
        sendTo(userId,{type:'coins_update',coins:getCoins(userId)});
        sendTo(msg.toUserId,{type:'gift_received',from,amount:amt2,coins:getCoins(msg.toUserId)});
        const gp={type:'pm',from,to:msg.toUserId,text:`🎁 Подарував ${amt2} ✈️!`,time:Date.now()};
        sendTo(msg.toUserId,gp);sendTo(userId,gp);
        break;
      }
      case 'admin_verify':{
        if(!isAdmin(userId))return;
        if(msg.verified)verifiedSet.add(msg.targetId);else verifiedSet.delete(msg.targetId);
        saveData();logAdmin(userId,msg.verified?'verify':'unverify',msg.targetId);
        broadcast({type:'verified_update',targetId:msg.targetId,verified:msg.verified});
        break;
      }
      case 'poll_send':{
        const poll=polls.get(msg.pollId); if(!poll)return;
        const ppkt={type:'poll_msg',from,poll,chatKey:msg.chatKey,time:Date.now()};
        if(msg.chatKey==='__all__')broadcast(ppkt,null);
        else if(msg.chatKey?.startsWith('grp_'))broadcastToGroup(msg.chatKey,ppkt);
        else{sendTo(msg.chatKey,ppkt);sendTo(userId,ppkt);}
        break;
      }
      case 'secret_msg':
        sendTo(msg.to,{type:'secret_msg',from,text:msg.text,ttl:msg.ttl||10,time:Date.now()});
        sendTo(userId,{type:'secret_msg',from,to:msg.to,text:msg.text,ttl:msg.ttl||10,time:Date.now()});
        break;
      case 'game_invite': sendTo(msg.to,{type:'game_invite',from,game:msg.game});break;
      case 'game_move':   sendTo(msg.to,{type:'game_move',from,game:msg.game,move:msg.move,state:msg.state});break;
      case 'avatar_update':{
        const p2=getProfile(userId)||{};p2.avatar=msg.avatar;profiles.set(userId,p2);saveData();
        if(clients.has(userId))clients.get(userId).user.avatar=msg.avatar;
        broadcast({type:'avatar_updated',userId,avatar:msg.avatar});
        break;
      }
      case 'channel_chat':{
        // Chat message in channel discussion
        const {channelId, text, audio, fileData, fileName, fileType} = msg;
        const ch = channels.get(channelId);
        if (!ch) return;
        const pkt = {
          type:'channel_chat', channelId,
          from, text:(text||'').slice(0,4000),
          audio:audio||null, fileData:fileData||null,
          fileName:fileName||null, fileType:fileType||null,
          time:Date.now()
        };
        // Broadcast to all subscribers
        for(const sub of ch.subscribers) sendTo(sub, pkt);
        break;
      }
      case 'ping':break;
      case 'admin_event':{
        if(!userId||!isAdmin(userId))return;
        const pkt={type:'admin_event',action:msg.action,eventId:msg.eventId,eventName:msg.eventName,from:clients.get(userId)?.user};
        broadcast(pkt);
        logAdmin(userId,'event_'+(msg.action||''),msg.eventId||'');
        break;
      }
    }
  });
  ws.on('close',()=>{
    if(userId){const u=clients.get(userId)?.user;clients.delete(userId);if(u)broadcast({type:'user_left',user:u,online:getOnline()});}
  });
});

// ── Start ─────────────────────────────────────────────────────
httpServer.listen(PORT,()=>{
  console.log(`\n🚀 Echo v5.0: ${BASE_URL}`);
  console.log('💡 help | list | bans | save\n');
});

const readline=require('readline');
const rl=readline.createInterface({input:process.stdin});
rl.on('line',line=>{
  line=line.trim();
  if(line==='help')console.log('list | bans | save | unban <email>');
  if(line==='list')for(const[,c]of clients)console.log(c.user.id,c.user.name);
  if(line==='bans')console.log([...banned].join('\n'));
  if(line==='save'){saveData();console.log('✅ Збережено');}
  if(line.startsWith('unban ')){const e=line.slice(6).trim();banned.delete(e);saveData();console.log('✅',e);}
});

app.use((err,req,res,next)=>{console.error(err.message);res.status(500).json({error:'Server error'});});
