// This textdoc will include all files needed for Anton's Node/Express futuristic browser
// with authentication, admin panel, and front-end

// Folder structure:
/*
anton-node-browser-full/
├─ index.js
├─ package.json
├─ vercel.json
├─ db/
│  └─ users.json (auto-created)
└─ public/
   ├─ index.html
   ├─ styles.css
   └─ app.js
*/

// index.js
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const serverless = require('serverless-http');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const DB_DIR = path.join(__dirname, 'db');
const USERS_FILE = path.join(DB_DIR, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const TOKEN_NAME = 'anton_token';

function ensureDB() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    const admin = {
      id: 'admin-1',
      email: 'antonkrupinski0@gmail.com',
      passwordHash: bcrypt.hashSync('Anton201309!'),
      name: 'Anton',
      isAdmin: true,
      banned: false
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify([admin], null, 2));
  }
}

function readUsers() {
  ensureDB();
  const raw = fs.readFileSync(USERS_FILE, 'utf8');
  return JSON.parse(raw);
}

function writeUsers(users) {
  ensureDB();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUserByEmail(email) {
  const users = readUsers();
  return users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
}

function getUserById(id) {
  const users = readUsers();
  return users.find(u => u.id === id);
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}

// --- Auth API ---
app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  if (findUserByEmail(email)) return res.status(400).json({ error: 'Email already exists' });
  const users = readUsers();
  const id = 'u-' + Date.now();
  const passwordHash = bcrypt.hashSync(password);
  const user = { id, email, passwordHash, name: name || email.split('@')[0], isAdmin: false, banned: false };
  users.push(user);
  writeUsers(users);
  const token = createToken({ id: user.id });
  res.cookie(TOKEN_NAME, token, { httpOnly: true, sameSite: 'lax' });
  res.json({ ok: true, user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  const user = findUserByEmail(email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  if (user.banned) return res.status(403).json({ error: 'BANNED', redirect: 'https://banned.antonkrupinski.com' });
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const token = createToken({ id: user.id });
  res.cookie(TOKEN_NAME, token, { httpOnly: true, sameSite: 'lax' });
  res.json({ ok: true, user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(TOKEN_NAME);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ user: null });
  const data = verifyToken(token);
  if (!data) return res.json({ user: null });
  const user = getUserById(data.id);
  if (!user) return res.json({ user: null });
  if (user.banned) return res.status(403).json({ error: 'BANNED', redirect: 'https://banned.antonkrupinski.com' });
  res.json({ user: { id: user.id, email: user.email, name: user.name, isAdmin: user.isAdmin } });
});

// --- Admin actions ---
function requireAdmin(req, res) {
  const token = req.cookies[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: 'Unauthorized' });
  const user = getUserById(data.id);
  if (!user || !user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  return user;
}

app.get('/api/users', (req, res) => {
  const admin = requireAdmin(req, res); if (!admin) return;
  const users = readUsers().map(u => ({ id: u.id, email: u.email, name: u.name, isAdmin: u.isAdmin, banned: u.banned }));
  res.json({ users });
});

app.post('/api/users/delete', (req, res) => {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { id } = req.body;
  let users = readUsers();
  users = users.filter(u => u.id !== id);
  writeUsers(users);
  res.json({ ok: true });
});

app.post('/api/users/toggle-admin', (req, res) => {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { id, makeAdmin } = req.body;
  const users = readUsers();
  const u = users.find(x => x.id === id);
  if (u) u.isAdmin = !!makeAdmin;
  writeUsers(users);
  res.json({ ok: true });
});

app.post('/api/users/ban', (req, res) => {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { id } = req.body;
  const users = readUsers();
  const u = users.find(x => x.id === id);
  if (u) u.banned = true;
  writeUsers(users);
  res.json({ ok: true });
});

app.post('/api/users/unban', (req, res) => {
  const admin = requireAdmin(req, res); if (!admin) return;
  const { id } = req.body;
  const users = readUsers();
  const u = users.find(x => x.id === id);
  if (u) u.banned = false;
  writeUsers(users);
  res.json({ ok: true });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

module.exports = serverless(app);
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Anton server listening on ${PORT}`));
}
