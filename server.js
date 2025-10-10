// A full-stack backend for the Bus Timetable app using Node.js, Express, and better-sqlite3.

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_SOURCE = "timetable.db";
const JSON_SOURCE = path.join(__dirname, 'buses.json');

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- DATABASE SETUP ---
const db = new Database(DB_SOURCE, { /* verbose: console.log */ });
console.log('Connected to the SQLite database.');

// Create table and perform one-time migration from JSON if needed
try {
    db.exec(`CREATE TABLE IF NOT EXISTS buses (
        id INTEGER PRIMARY KEY,
        route TEXT,
        operator TEXT,
        departsFrom TEXT,
        arrivesAt TEXT,
        departureTime TEXT,
        arrivalTime TEXT,
        price TEXT,
        stops TEXT,
        availability TEXT,
        sortOrder INTEGER
    )`);

    const countStmt = db.prepare("SELECT COUNT(*) as count FROM buses");
    const { count } = countStmt.get();

    if (count === 0 && fs.existsSync(JSON_SOURCE)) {
        console.log("Empty database, attempting to import from buses.json...");
        const busesToImport = JSON.parse(fs.readFileSync(JSON_SOURCE, 'utf8'));
        
        const insert = db.prepare("INSERT INTO buses (id, route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability, sortOrder) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
        
        const importTransaction = db.transaction((buses) => {
            for (const [index, bus] of buses.entries()) {
                insert.run(bus.id, bus.route, bus.operator, bus.departsFrom, bus.arrivesAt, bus.departureTime, bus.arrivalTime, bus.price, JSON.stringify(bus.stops), JSON.stringify(bus.availability), index);
            }
        });

        importTransaction(busesToImport);
        console.log(`Successfully imported ${busesToImport.length} buses.`);
    }
} catch (err) {
    console.error("Database setup error:", err.message);
}


// --- HELPER FUNCTION to parse JSON from DB results ---
const parseBusData = (bus) => {
    if (bus) {
        bus.stops = JSON.parse(bus.stops || '[]');
        bus.availability = JSON.parse(bus.availability || '[]');
    }
    return bus;
};


// --- AUTHENTICATION ---
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'password'; 
const AUTH_TOKEN = 'secret-jwt-token'; 

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        res.json({ message: 'Login successful', token: AUTH_TOKEN });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

const checkAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === AUTH_TOKEN) {
        next();
    } else {
        return res.sendStatus(401);
    }
};

// --- PUBLIC API ROUTES ---
app.get('/api/search', (req, res) => {
    const { from, to, date } = req.query;
    if (!from || !to) {
        return res.status(400).json({ error: 'Missing "from" or "to" query parameters.' });
    }

    try {
        const sql = `SELECT * FROM buses WHERE departsFrom LIKE ? AND arrivesAt LIKE ? ORDER BY departureTime ASC`;
        const params = ['%' + from + '%', '%' + to + '%'];
        const stmt = db.prepare(sql);
        let results = stmt.all(params).map(parseBusData);

        if (date) {
            const searchDate = new Date(date);
            searchDate.setHours(12);
            const dayOfWeek = searchDate.toLocaleString('en-US', { weekday: 'long' });
            results = results.filter(bus => bus.availability.includes(dayOfWeek));
        }
        res.json(results);
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

// --- ADMIN API ROUTES (PROTECTED) ---
app.get('/api/buses', checkAuth, (req, res) => {
    try {
        const stmt = db.prepare("SELECT * FROM buses ORDER BY sortOrder ASC");
        const rows = stmt.all().map(parseBusData);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

app.post('/api/buses', checkAuth, (req, res) => {
    const { route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability } = req.body;
    try {
        const orderStmt = db.prepare("SELECT MAX(sortOrder) as maxOrder FROM buses");
        const { maxOrder } = orderStmt.get();
        const nextOrder = (maxOrder === null ? 0 : maxOrder) + 1;
        
        const sql = `INSERT INTO buses (route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability, sortOrder) VALUES (?,?,?,?,?,?,?,?,?,?)`;
        const params = [route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, JSON.stringify(stops), JSON.stringify(availability), nextOrder];
        const stmt = db.prepare(sql);
        const info = stmt.run(params);

        res.status(201).json({ id: info.lastInsertRowid, ...req.body, sortOrder: nextOrder });
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

app.put('/api/buses/:id', checkAuth, (req, res) => {
    const { route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, stops, availability } = req.body;
    try {
        const sql = `UPDATE buses SET route = ?, operator = ?, departsFrom = ?, arrivesAt = ?, departureTime = ?, arrivalTime = ?, price = ?, stops = ?, availability = ? WHERE id = ?`;
        const params = [route, operator, departsFrom, arrivesAt, departureTime, arrivalTime, price, JSON.stringify(stops), JSON.stringify(availability), req.params.id];
        const stmt = db.prepare(sql);
        const info = stmt.run(params);
        res.json({ message: 'Bus updated successfully', changes: info.changes });
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

app.delete('/api/buses/:id', checkAuth, (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM buses WHERE id = ?');
        const info = stmt.run(req.params.id);
        if (info.changes === 0) {
            return res.status(404).json({ message: 'Bus not found' });
        }
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

app.post('/api/buses/order', checkAuth, (req, res) => {
    const { orderedIds } = req.body;
    if (!Array.isArray(orderedIds)) {
        return res.status(400).json({ message: 'orderedIds must be an array' });
    }

    try {
        const updateStmt = db.prepare('UPDATE buses SET sortOrder = ? WHERE id = ?');
        const reorderTransaction = db.transaction((ids) => {
            for (const [index, id] of ids.entries()) {
                updateStmt.run(index, id);
            }
        });
        reorderTransaction(orderedIds);
        res.json({ message: 'Bus order updated successfully.' });
    } catch (err) {
        res.status(500).json({ "error": err.message });
    }
});

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

