// A full-stack backend for the Bus Timetable app using Node.js and Express.

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static('public'));


// --- IN-MEMORY DATABASE ---
// In a real application, use a persistent database like PostgreSQL or MongoDB.
let busDatabase = [
    { id: 1, route: 'X93', operator: 'National Express', departsFrom: 'London Victoria', arrivesAt: 'Manchester Piccadilly', departureTime: '08:00', arrivalTime: '12:30', price: '£25.00', stops: ['Milton Keynes', 'Birmingham Coach Station', 'Stoke-on-Trent'] },
    { id: 2, route: 'M10', operator: 'MegaBus', departsFrom: 'London Victoria', arrivesAt: 'Manchester Piccadilly', departureTime: '09:30', arrivalTime: '14:15', price: '£22.50', stops: ['Luton Airport', 'Coventry', 'Birmingham Airport'] },
    { id: 3, route: 'G1', operator: 'GoAhead', departsFrom: 'Oxford City Centre', arrivesAt: 'Cambridge City Centre', departureTime: '10:00', arrivalTime: '12:30', price: '£15.00', stops: ['Bicester', 'Milton Keynes', 'Bedford'] },
    { id: 4, route: 'S5', operator: 'Stagecoach', departsFrom: 'Bristol Temple Meads', arrivesAt: 'Birmingham New Street', departureTime: '11:00', arrivalTime: '13:00', price: '£18.00', stops: ['Gloucester', 'Worcester'] }
];
let nextId = 5;

// --- AUTHENTICATION ---
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'password'; // In production, use environment variables and hashed passwords!
const AUTH_TOKEN = 'secret-jwt-token'; // In production, use a library like JWT to generate tokens.

// Login route
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        res.json({ message: 'Login successful', token: AUTH_TOKEN });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Auth middleware to protect admin routes
const checkAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (token == null) {
        return res.status(401).json({ message: 'No token provided' });
    }
    if (token === AUTH_TOKEN) {
        next(); // Token is valid, proceed to the route
    } else {
        return res.status(403).json({ message: 'Invalid token' });
    }
};


// --- PUBLIC API ROUTES ---

// Search route for customer interface
app.get('/api/search', (req, res) => {
    const { from, to } = req.query;
    if (!from || !to) {
        return res.status(400).json({ error: 'Missing "from" or "to" query parameters.' });
    }
    const fromLower = from.toLowerCase();
    const toLower = to.toLowerCase();
    const results = busDatabase.filter(bus => 
        bus.departsFrom.toLowerCase().includes(fromLower) &&
        bus.arrivesAt.toLowerCase().includes(toLower)
    );
    res.json(results);
});


// --- ADMIN API ROUTES (PROTECTED) ---

// GET all buses
app.get('/api/buses', checkAuth, (req, res) => {
    res.json(busDatabase);
});

// GET a single bus by ID
app.get('/api/buses/:id', checkAuth, (req, res) => {
    const bus = busDatabase.find(b => b.id === parseInt(req.params.id));
    if (bus) {
        res.json(bus);
    } else {
        res.status(404).json({ message: 'Bus not found' });
    }
});

// POST (add) a new bus
app.post('/api/buses', checkAuth, (req, res) => {
    const newBus = { id: nextId++, ...req.body };
    busDatabase.push(newBus);
    res.status(201).json(newBus);
});

// PUT (update) a bus
app.put('/api/buses/:id', checkAuth, (req, res) => {
    const busIndex = busDatabase.findIndex(b => b.id === parseInt(req.params.id));
    if (busIndex > -1) {
        busDatabase[busIndex] = { ...busDatabase[busIndex], ...req.body };
        res.json(busDatabase[busIndex]);
    } else {
        res.status(404).json({ message: 'Bus not found' });
    }
});

// DELETE a bus
app.delete('/api/buses/:id', checkAuth, (req, res) => {
    const busIndex = busDatabase.findIndex(b => b.id === parseInt(req.params.id));
    if (busIndex > -1) {
        busDatabase.splice(busIndex, 1);
        res.status(204).send(); // No content
    } else {
        res.status(404).json({ message: 'Bus not found' });
    }
});

// POST (update) the order of buses
app.post('/api/buses/order', checkAuth, (req, res) => {
    const { orderedIds } = req.body; // Expects an array of bus IDs in the new order
    if (!Array.isArray(orderedIds)) {
        return res.status(400).json({ message: 'orderedIds must be an array' });
    }
    
    const orderedBuses = orderedIds.map(id => busDatabase.find(bus => bus.id === id));
    
    // Check for missing buses
    if (orderedBuses.some(b => b === undefined)) {
         return res.status(400).json({ message: 'One or more bus IDs are invalid.' });
    }
    
    busDatabase = orderedBuses;
    res.json({ message: 'Bus order updated successfully.' });
});

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});


