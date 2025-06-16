import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs/promises';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = 3000;
const JWT_SECRET = 'secret-key';
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '60s'; 

const usersFilePath = path.join(__dirname, '..', 'public', 'data', 'users.json');

async function readUsers() {
    const data = await fs.readFile(usersFilePath, 'utf8');
    return JSON.parse(data);
}

async function saveUsers(users) {
    await fs.writeFile(usersFilePath, JSON.stringify(users, null, 2));
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (erro, user) => {
        if (erro) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

async function verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(cors()); 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/', async (req, res) => {
    const { name, password } = req.body;
    
    const users = await readUsers();
    const user = users.find(user => user.name === name);
    
    if (!user || !(await verifyPassword(password, user.password))) {
        return res.render('index', { error: 'Invalid name or password' });
    }
    
    const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    
    res.render('partials/login-success', { user: user, token: token });
});

app.get('/auth/register', (req, res) => {
    res.render('partials/register');
});

app.post('/auth/register', async (req, res) => {
    const { name, password } = req.body;
    const users = await readUsers();
    const existingUser = users.find(user => user.name === name);
    if (existingUser) {
        return res.render('partials/register', { error: 'User with this name already exists' });
    }
    
    const hashedPassword = await hashPassword(password);
    const newUser = {
        id: uuidv4(),
        name,
        password: hashedPassword,
        createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    await saveUsers(users);
    
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { name, password } = req.body;
    const users = await readUsers();
    const user = users.find(u => u.name === name);
    
    if (!user || !(await verifyPassword(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    
    res.json({ token, user: { id: user.id, name: user.name }, expiresIn: TOKEN_EXPIRY });
});

app.post('/api/register', async (req, res) => {
    const { name, password } = req.body;
    const users = await readUsers();
    const existingUser = users.find(u => u.name === name);

    if (existingUser) {
        return res.status(400).json({ error: 'User with this name already exists' });
    }
    
    const hashedPassword = await hashPassword(password);
    const newUser = {
        id: uuidv4(),
        name,
        password: hashedPassword,
        createdAt: new Date().toISOString()
    };
    
    const token = jwt.sign({ id: newUser.id, name: newUser.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    
    users.push(newUser);
    await saveUsers(users);
    
    res.json({ token, user: { id: newUser.id, name: newUser.name }, expiresIn: TOKEN_EXPIRY });
});

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

app.post('/api/verify-token', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ error: 'Token required' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: { id: decoded.id, name: decoded.name } });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(403).json({ error: 'Invalid token' });
    }
});

app.get('/api/users', authenticateToken, async (req, res) => {
    const users = await readUsers();
    const usersData = users.map(user => ({
        id: user.id,
        name: user.name,
        createdAt: user.createdAt
    }));
    res.json(usersData);
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});