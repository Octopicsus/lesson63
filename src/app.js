import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs/promises';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import session from 'express-session';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = 3000;
const JWT_SECRET = 'secret-key';
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '24h'; 

const usersFilePath = path.join(__dirname, '..', 'public', 'data', 'users.json');

async function readUsers() {
    const data = await fs.readFile(usersFilePath, 'utf8');
    return JSON.parse(data);
}

async function saveUsers(users) {
    await fs.writeFile(usersFilePath, JSON.stringify(users, null, 2));
}

async function registerUser(name, password) {
    const users = await readUsers();
    const existingUser = users.find(user => user.name === name);
    
    if (existingUser) {
        throw new Error('User with this name already exists');
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
    return newUser;
}

async function verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
}, async (username, password, done) => {
    try {
        const users = await readUsers();
        const user = users.find(user => user.name === username);
        
        if (!user) {
            return done(null, false, { message: 'Invalid username or password' });
        }
        
        const isValidPassword = await verifyPassword(password, user.password);
        if (!isValidPassword) {
            return done(null, false, { message: 'Invalid username or password' });
        }
        
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const users = await readUsers();
        const user = users.find(user => user.id === id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: 'passport-secret-key',
    resave: false,
    saveUninitialized: false,
}));

app.use(cors()); 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(returnJson = false) {
    return (req, res, next) => {
        if (req.isAuthenticated()) {
            return next();
        }
        
        if (returnJson) {
            return res.status(401).json({ error: 'Authentication required' });
        } else {
            return res.redirect('/');
        }
    };
}

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/auth/login', passport.authenticate('local', {
    successRedirect: '/protected',
    failureRedirect: '/',
    failureMessage: true
}));

app.post('/auth/logout', (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        req.session.destroy(() => {
            res.redirect('/');
        });
    });
});

app.get('/auth/register', (req, res) => {
    res.render('partials/register');
});

app.post('/auth/register', async (req, res) => {
    const { name, password } = req.body;
    
    try {
        const newUser = await registerUser(name, password);
        
        req.login(newUser, (error) => {
            if (error) {
                return res.render('partials/register', { error: 'Registration successful but login failed' });
            }
            res.redirect('/');
        });
    } catch (error) {
        res.render('partials/register', { error: error.message });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (error, user, info) => {
        if (error) {
            return res.status(500).json({ error: 'Authentication error' });
        }
        if (!user) {
            return res.status(401).json({ error: info.message || 'Invalid credentials' });
        }
        
        req.logIn(user, (error) => {
            if (error) {
                return res.status(500).json({ error: 'Login error' });
            }
            
            const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
            res.json({ 
                token, 
                user: { id: user.id, name: user.name }, 
                expiresIn: TOKEN_EXPIRY 
            });
        });
    })(req, res, next);
});

app.post('/api/register', async (req, res) => {
    const { name, password } = req.body;
    
    try {
        const newUser = await registerUser(name, password);
        
        req.logIn(newUser, (error) => {
            if (error) {
                return res.status(500).json({ error: 'Registration successful but login failed' });
            }
            
            const token = jwt.sign({ id: newUser.id, name: newUser.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
            res.json({ 
                token, 
                user: { id: newUser.id, name: newUser.name }, 
                expiresIn: TOKEN_EXPIRY 
            });
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/logout', ensureAuthenticated(true), (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        req.session.destroy(() => {
            res.json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/protected', ensureAuthenticated(), (req, res) => {
    res.render('partials/protected', { user: req.user });
});

app.get('/api/protected', ensureAuthenticated(true), (req, res) => {
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

app.get('/api/users', ensureAuthenticated(true), async (req, res) => {
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