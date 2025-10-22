// A full-stack backend for the Bus Timetable app using Node.js, Express, and better-sqlite3.

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_SOURCE = 'timetable.db';
const JSON_SOURCE = path.join(__dirname, 'buses.json');

// --- LIGHTWEIGHT ENV LOADER ---
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (match && !process.env[match[1]]) {
      const value = match[2].replace(/^"|"$/g, '');
      process.env[match[1]] = value;
    }
  });
}

const CONFIG = {
  jwtSecret: process.env.JWT_SECRET || 'development-secret-change-me',
  adminEmail: process.env.ADMIN_EMAIL || 'admin@example.com',
  adminPassword: process.env.ADMIN_PASSWORD || 'change-me-now',
};

// --- HELPERS ---
const base64url = (value) =>
  Buffer.from(value).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const decodeBase64url = (value) => {
  const padLength = (4 - (value.length % 4)) % 4;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized + '='.repeat(padLength), 'base64').toString('utf8');
};

const signJwt = (payload, options = {}) => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const expSeconds = options.expiresIn || 60 * 60; // 1 hour default
  const data = { ...payload, exp: Math.floor(Date.now() / 1000) + expSeconds };
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(data));
  const signature = crypto
    .createHmac('sha256', CONFIG.jwtSecret)
    .update(`${headerEncoded}.${payloadEncoded}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${headerEncoded}.${payloadEncoded}.${signature}`;
};

const verifyJwt = (token) => {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, signaturePart] = parts;
  const expectedSig = crypto
    .createHmac('sha256', CONFIG.jwtSecret)
    .update(`${headerPart}.${payloadPart}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (expectedSig.length !== signaturePart.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(signaturePart))) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(decodeBase64url(payloadPart));
  } catch (err) {
    return null;
  }
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }
  return payload;
};

const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
};

const verifyPassword = (password, stored) => {
  const [salt, key] = stored.split(':');
  if (!salt || !key) return false;
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const storedKey = Buffer.from(key, 'hex');
  return crypto.timingSafeEqual(derivedKey, storedKey);
};

const parseJsonColumn = (value, fallback) => {
  try {
    return JSON.parse(value || fallback);
  } catch (err) {
    return JSON.parse(fallback);
  }
};

const nowIso = () => new Date().toISOString();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'sl-bus-timetable');
  next();
});
app.use(express.static(__dirname));

// --- DATABASE SETUP ---
const db = new Database(DB_SOURCE);
console.log('Connected to the SQLite database.');

const ensureColumn = (table, column, definition, afterAdd) => {
  const infoStmt = db.prepare(`PRAGMA table_info(${table})`);
  const columns = infoStmt.all();
  const exists = columns.some((col) => col.name === column);
  if (!exists) {
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      if (typeof afterAdd === 'function') afterAdd();
    } catch (err) {
      console.warn(`Skipping column ${column} on ${table}:`, err.message);
    }
  }
};

try {
  db.exec(`CREATE TABLE IF NOT EXISTS buses (
    id INTEGER PRIMARY KEY,
    route TEXT NOT NULL,
    operator TEXT NOT NULL,
    departsFrom TEXT NOT NULL,
    arrivesAt TEXT NOT NULL,
    departureTime TEXT NOT NULL,
    arrivalTime TEXT,
    price TEXT,
    stops TEXT DEFAULT '[]',
    availability TEXT DEFAULT '[]',
    expresswayEntrance TEXT,
    expresswayExit TEXT,
    status TEXT DEFAULT 'Scheduled',
    sortOrder INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT (datetime('now')),
    updatedAt TEXT DEFAULT (datetime('now'))
  )`);

  ensureColumn('buses', 'expresswayEntrance', 'TEXT');
  ensureColumn('buses', 'expresswayExit', 'TEXT');
  ensureColumn('buses', 'status', "TEXT DEFAULT 'Scheduled'", () => {
    db.exec("UPDATE buses SET status = 'Scheduled' WHERE status IS NULL OR status = ''");
  });
  ensureColumn('buses', 'createdAt', 'TEXT', () => {
    db.exec("UPDATE buses SET createdAt = datetime('now') WHERE createdAt IS NULL OR createdAt = ''");
  });
  ensureColumn('buses', 'updatedAt', 'TEXT', () => {
    db.exec("UPDATE buses SET updatedAt = datetime('now') WHERE updatedAt IS NULL OR updatedAt = ''");
  });

  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    depot TEXT,
    passwordHash TEXT NOT NULL,
    createdAt TEXT DEFAULT (datetime('now')),
    updatedAt TEXT DEFAULT (datetime('now'))
  )`);

  const busCountStmt = db.prepare('SELECT COUNT(*) as count FROM buses');
  const { count } = busCountStmt.get();
  if (count === 0 && fs.existsSync(JSON_SOURCE)) {
    console.log('Empty database, attempting to import from buses.json...');
    const busesToImport = JSON.parse(fs.readFileSync(JSON_SOURCE, 'utf8'));
    const insert = db.prepare(
      `INSERT INTO buses (route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability, expresswayEntrance, expresswayExit, status, sortOrder, createdAt, updatedAt)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    );
    const importTransaction = db.transaction((buses) => {
      buses.forEach((bus, index) => {
        insert.run(
          bus.route,
          bus.operator,
          bus.departsFrom,
          bus.arrivesAt,
          bus.departureTime,
          bus.arrivalTime || null,
          bus.price || null,
          JSON.stringify(bus.stops || []),
          JSON.stringify(bus.availability || []),
          bus.expresswayEntrance || null,
          bus.expresswayExit || null,
          bus.status || 'Scheduled',
          typeof bus.sortOrder === 'number' ? bus.sortOrder : index,
          bus.createdAt || nowIso(),
          bus.updatedAt || nowIso()
        );
      });
    });
    importTransaction(busesToImport);
    console.log(`Successfully imported ${busesToImport.length} buses.`);
  }

  const userCountStmt = db.prepare('SELECT COUNT(*) as count FROM users');
  const { count: userCount } = userCountStmt.get();
  if (userCount === 0) {
    const insertAdmin = db.prepare(
      `INSERT INTO users (email, role, depot, passwordHash, createdAt, updatedAt)
       VALUES (@email, @role, @depot, @passwordHash, @createdAt, @updatedAt)`
    );
    insertAdmin.run({
      email: CONFIG.adminEmail,
      role: 'admin',
      depot: null,
      passwordHash: hashPassword(CONFIG.adminPassword),
      createdAt: nowIso(),
      updatedAt: nowIso(),
    });
    console.log(`Provisioned default admin account for ${CONFIG.adminEmail}`);
  }
} catch (err) {
  console.error('Database setup error:', err.message);
}

// --- HELPER FUNCTIONS ---
const mapBusRow = (row) => ({
  ...row,
  stops: parseJsonColumn(row.stops, '[]'),
  availability: parseJsonColumn(row.availability, '[]'),
});

const validateBusPayload = (payload) => {
  const errors = [];
  const requiredFields = ['route', 'operator', 'departsFrom', 'arrivesAt', 'departureTime'];
  requiredFields.forEach((field) => {
    if (!payload[field] || typeof payload[field] !== 'string' || !payload[field].trim()) {
      errors.push(`${field} is required`);
    }
  });
  if (payload.arrivalTime && !/^\d{2}:\d{2}$/.test(payload.arrivalTime)) {
    errors.push('arrivalTime must be HH:MM');
  }
  if (payload.departureTime && !/^\d{2}:\d{2}$/.test(payload.departureTime)) {
    errors.push('departureTime must be HH:MM');
  }
  if (payload.availability && !Array.isArray(payload.availability)) {
    errors.push('availability must be an array');
  }
  if (payload.stops && !Array.isArray(payload.stops)) {
    errors.push('stops must be an array');
  }
  return errors;
};

const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const payload = verifyJwt(token);
  if (!payload) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  req.user = payload;
  next();
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  next();
};

const getUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const getUserById = db.prepare('SELECT * FROM users WHERE id = ?');

// --- AUTH ROUTES ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  try {
    const user = getUserByEmail.get(email.toLowerCase());
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    const token = signJwt({ id: user.id, email: user.email, role: user.role, depot: user.depot });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, depot: user.depot } });
  } catch (err) {
    res.status(500).json({ message: 'Unable to process login.' });
  }
});

app.get('/api/me', authenticate, (req, res) => {
  const user = getUserById.get(req.user.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.json({ id: user.id, email: user.email, role: user.role, depot: user.depot });
});

// --- PUBLIC API ROUTES ---
app.get('/api/locations', (req, res) => {
  try {
    const rows = db.prepare('SELECT departsFrom, arrivesAt, expresswayEntrance, expresswayExit FROM buses').all();
    const locations = new Set();
    rows.forEach((row) => {
      [row.departsFrom, row.arrivesAt, row.expresswayEntrance, row.expresswayExit].forEach((value) => {
        if (value) {
          locations.add(value.trim());
        }
      });
    });
    res.json({ locations: Array.from(locations).sort((a, b) => a.localeCompare(b)) });
  } catch (err) {
    res.status(500).json({ message: 'Failed to load locations.' });
  }
});

app.get('/api/search', (req, res) => {
  const { from, to, date } = req.query;
  if (!from || !to || !date) {
    return res.status(400).json({ message: 'from, to and date query parameters are required.' });
  }
  try {
    const stmt = db.prepare(
      `SELECT * FROM buses WHERE (LOWER(departsFrom) = LOWER(?) OR LOWER(expresswayEntrance) = LOWER(?))
        AND (LOWER(arrivesAt) = LOWER(?) OR LOWER(expresswayExit) = LOWER(?))
        ORDER BY departureTime ASC`
    );
    const rows = stmt.all(from, from, to, to).map(mapBusRow);
    const searchDate = new Date(date);
    searchDate.setHours(12);
    const dayOfWeek = searchDate.toLocaleString('en-US', { weekday: 'long' });
    const filtered = rows.filter((bus) => !bus.availability.length || bus.availability.includes(dayOfWeek));
    res.json({
      buses: filtered,
      meta: {
        from,
        to,
        dayOfWeek,
        total: filtered.length,
      },
    });
  } catch (err) {
    res.status(500).json({ message: 'Search failed.' });
  }
});

// --- BUS ADMIN ROUTES ---
app.get('/api/buses', authenticate, requireRole('admin'), (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM buses ORDER BY sortOrder ASC, departureTime ASC').all().map(mapBusRow);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Unable to load buses.' });
  }
});

app.post('/api/buses', authenticate, requireRole('admin'), (req, res) => {
  const payload = req.body || {};
  const errors = validateBusPayload(payload);
  if (errors.length) {
    return res.status(400).json({ message: 'Validation error', errors });
  }
  try {
    const orderStmt = db.prepare('SELECT IFNULL(MAX(sortOrder), -1) as maxOrder FROM buses');
    const { maxOrder } = orderStmt.get();
    const nextOrder = maxOrder + 1;
    const stmt = db.prepare(
      `INSERT INTO buses (route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability, expresswayEntrance, expresswayExit, status, sortOrder, createdAt, updatedAt)
       VALUES (@route, @operator, @departsFrom, @arrivesAt, @departureTime, @arrivalTime, @price, @stops, @availability, @expresswayEntrance, @expresswayExit, 'Scheduled', @sortOrder, @createdAt, @updatedAt)`
    );
    const result = stmt.run({
      route: payload.route.trim(),
      operator: payload.operator.trim(),
      departsFrom: payload.departsFrom.trim(),
      arrivesAt: payload.arrivesAt.trim(),
      departureTime: payload.departureTime.trim(),
      arrivalTime: payload.arrivalTime ? payload.arrivalTime.trim() : null,
      price: payload.price ? payload.price.trim() : null,
      stops: JSON.stringify(payload.stops || []),
      availability: JSON.stringify(payload.availability || []),
      expresswayEntrance: payload.expresswayEntrance ? payload.expresswayEntrance.trim() : null,
      expresswayExit: payload.expresswayExit ? payload.expresswayExit.trim() : null,
      sortOrder: nextOrder,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    });
    const created = db.prepare('SELECT * FROM buses WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(mapBusRow(created));
  } catch (err) {
    res.status(500).json({ message: 'Unable to create bus.' });
  }
});

app.put('/api/buses/:id', authenticate, requireRole('admin'), (req, res) => {
  const payload = req.body || {};
  const errors = validateBusPayload(payload);
  if (errors.length) {
    return res.status(400).json({ message: 'Validation error', errors });
  }
  try {
    const stmt = db.prepare(
      `UPDATE buses SET route=@route, operator=@operator, departsFrom=@departsFrom, arrivesAt=@arrivesAt,
        departureTime=@departureTime, arrivalTime=@arrivalTime, price=@price, stops=@stops, availability=@availability,
        expresswayEntrance=@expresswayEntrance, expresswayExit=@expresswayExit, updatedAt=@updatedAt
       WHERE id=@id`
    );
    const info = stmt.run({
      id: req.params.id,
      route: payload.route.trim(),
      operator: payload.operator.trim(),
      departsFrom: payload.departsFrom.trim(),
      arrivesAt: payload.arrivesAt.trim(),
      departureTime: payload.departureTime.trim(),
      arrivalTime: payload.arrivalTime ? payload.arrivalTime.trim() : null,
      price: payload.price ? payload.price.trim() : null,
      stops: JSON.stringify(payload.stops || []),
      availability: JSON.stringify(payload.availability || []),
      expresswayEntrance: payload.expresswayEntrance ? payload.expresswayEntrance.trim() : null,
      expresswayExit: payload.expresswayExit ? payload.expresswayExit.trim() : null,
      updatedAt: nowIso(),
    });
    if (!info.changes) {
      return res.status(404).json({ message: 'Bus not found' });
    }
    const updated = db.prepare('SELECT * FROM buses WHERE id = ?').get(req.params.id);
    res.json(mapBusRow(updated));
  } catch (err) {
    res.status(500).json({ message: 'Unable to update bus.' });
  }
});

app.delete('/api/buses/:id', authenticate, requireRole('admin'), (req, res) => {
  try {
    const stmt = db.prepare('DELETE FROM buses WHERE id = ?');
    const info = stmt.run(req.params.id);
    if (!info.changes) {
      return res.status(404).json({ message: 'Bus not found' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Unable to delete bus.' });
  }
});

app.post('/api/buses/order', authenticate, requireRole('admin'), (req, res) => {
  const { orderedIds } = req.body || {};
  if (!Array.isArray(orderedIds)) {
    return res.status(400).json({ message: 'orderedIds must be an array' });
  }
  try {
    const updateStmt = db.prepare('UPDATE buses SET sortOrder = ?, updatedAt = ? WHERE id = ?');
    const reorderTransaction = db.transaction((ids) => {
      ids.forEach((id, index) => {
        updateStmt.run(index, nowIso(), id);
      });
    });
    reorderTransaction(orderedIds);
    res.json({ message: 'Bus order updated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Unable to reorder buses.' });
  }
});

app.patch('/api/buses/:id/status', authenticate, requireRole('admin', 'timekeeper'), (req, res) => {
  const { status } = req.body || {};
  const allowedStatuses = ['Scheduled', 'Departed', 'Arrived', 'Delayed', 'Cancelled'];
  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid status' });
  }
  try {
    const stmt = db.prepare('UPDATE buses SET status = ?, updatedAt = ? WHERE id = ?');
    const info = stmt.run(status, nowIso(), req.params.id);
    if (!info.changes) {
      return res.status(404).json({ message: 'Bus not found' });
    }
    res.json({ message: 'Status updated' });
  } catch (err) {
    res.status(500).json({ message: 'Unable to update status.' });
  }
});

// --- TIMEKEEPER ROUTES ---
app.get('/api/timekeeper/schedule/today', authenticate, requireRole('admin', 'timekeeper'), (req, res) => {
  const depot = req.query.depot || req.user.depot;
  if (!depot) {
    return res.status(400).json({ message: 'Depot is required' });
  }
  const today = new Date().toLocaleString('en-US', { weekday: 'long' });
  try {
    const stmt = db.prepare(
      `SELECT * FROM buses WHERE LOWER(departsFrom) = LOWER(?) AND (availability = '[]' OR availability LIKE '%' || ? || '%')
       ORDER BY departureTime ASC`
    );
    const rows = stmt.all(depot, today).map(mapBusRow);
    const filtered = rows.filter((bus) => !bus.availability.length || bus.availability.includes(today));
    res.json({ depot, day: today, buses: filtered });
  } catch (err) {
    res.status(500).json({ message: 'Unable to load schedule.' });
  }
});

app.post('/api/timekeeper/buses', authenticate, requireRole('admin', 'timekeeper'), (req, res) => {
  const payload = req.body || {};
  const depot = req.user.depot || payload.departsFrom;
  if (!depot) {
    return res.status(400).json({ message: 'Depot is required to add a bus.' });
  }
  const minimalPayload = {
    route: payload.route,
    operator: payload.operator,
    departsFrom: depot,
    arrivesAt: payload.arrivesAt,
    departureTime: payload.departureTime,
    arrivalTime: payload.arrivalTime || null,
    price: payload.price || null,
    stops: payload.stops || [],
    availability: payload.availability || [],
    expresswayEntrance: payload.expresswayEntrance || null,
    expresswayExit: payload.expresswayExit || null,
  };
  const errors = validateBusPayload(minimalPayload);
  if (errors.length) {
    return res.status(400).json({ message: 'Validation error', errors });
  }
  try {
    const orderStmt = db.prepare('SELECT IFNULL(MAX(sortOrder), -1) as maxOrder FROM buses');
    const { maxOrder } = orderStmt.get();
    const nextOrder = maxOrder + 1;
    const stmt = db.prepare(
      `INSERT INTO buses (route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability, expresswayEntrance, expresswayExit, status, sortOrder, createdAt, updatedAt)
       VALUES (@route, @operator, @departsFrom, @arrivesAt, @departureTime, @arrivalTime, @price, @stops, @availability, @expresswayEntrance, @expresswayExit, 'Scheduled', @sortOrder, @createdAt, @updatedAt)`
    );
    const result = stmt.run({
      route: minimalPayload.route.trim(),
      operator: minimalPayload.operator.trim(),
      departsFrom: depot.trim(),
      arrivesAt: minimalPayload.arrivesAt.trim(),
      departureTime: minimalPayload.departureTime.trim(),
      arrivalTime: minimalPayload.arrivalTime ? minimalPayload.arrivalTime.trim() : null,
      price: minimalPayload.price ? minimalPayload.price.trim() : null,
      stops: JSON.stringify(minimalPayload.stops || []),
      availability: JSON.stringify(minimalPayload.availability || []),
      expresswayEntrance: minimalPayload.expresswayEntrance ? minimalPayload.expresswayEntrance.trim() : null,
      expresswayExit: minimalPayload.expresswayExit ? minimalPayload.expresswayExit.trim() : null,
      sortOrder: nextOrder,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    });
    const created = db.prepare('SELECT * FROM buses WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(mapBusRow(created));
  } catch (err) {
    res.status(500).json({ message: 'Unable to create bus.' });
  }
});

// --- USER MANAGEMENT ROUTES ---
app.get('/api/users', authenticate, requireRole('admin'), (req, res) => {
  try {
    const rows = db.prepare('SELECT id, email, role, depot, createdAt, updatedAt FROM users ORDER BY email ASC').all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Unable to load users.' });
  }
});

app.post('/api/users', authenticate, requireRole('admin'), (req, res) => {
  const { email, password, role, depot } = req.body || {};
  const errors = [];
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) errors.push('Valid email is required');
  if (!password || password.length < 8) errors.push('Password must be at least 8 characters long');
  if (!['admin', 'timekeeper'].includes(role)) errors.push('Role must be admin or timekeeper');
  if (role === 'timekeeper' && (!depot || !depot.trim())) errors.push('Depot is required for timekeepers');
  if (errors.length) {
    return res.status(400).json({ message: 'Validation error', errors });
  }
  try {
    const existing = getUserByEmail.get(email.toLowerCase());
    if (existing) {
      return res.status(409).json({ message: 'A user with this email already exists.' });
    }
    const stmt = db.prepare(
      `INSERT INTO users (email, role, depot, passwordHash, createdAt, updatedAt)
       VALUES (@email, @role, @depot, @passwordHash, @createdAt, @updatedAt)`
    );
    const result = stmt.run({
      email: email.toLowerCase(),
      role,
      depot: depot ? depot.trim() : null,
      passwordHash: hashPassword(password),
      createdAt: nowIso(),
      updatedAt: nowIso(),
    });
    const created = getUserById.get(result.lastInsertRowid);
    res.status(201).json({ id: created.id, email: created.email, role: created.role, depot: created.depot });
  } catch (err) {
    res.status(500).json({ message: 'Unable to create user.' });
  }
});

app.delete('/api/users/:id', authenticate, requireRole('admin'), (req, res) => {
  const userId = Number(req.params.id);
  if (userId === req.user.id) {
    return res.status(400).json({ message: 'You cannot delete your own account.' });
  }
  try {
    const stmt = db.prepare('DELETE FROM users WHERE id = ?');
    const info = stmt.run(userId);
    if (!info.changes) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ message: 'Unable to delete user.' });
  }
});

// --- FALLBACK ROUTES ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.redirect('/admin.html');
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

