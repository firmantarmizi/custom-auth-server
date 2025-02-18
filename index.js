const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const COOKIE_NAME = process.env.COOKIE_NAME || 'auth-token';
const VALIDITY = parseInt(process.env.VALIDITY || '1800'); // 30 minutes
const HTPASSWD_PATH = process.env.HTPASSWD_PATH || '/auth/.htpasswd';

// Function to parse htpasswd file
function parseHtpasswd() {
    try {
        const content = fs.readFileSync(HTPASSWD_PATH, 'utf-8');
        const users = {};
        content.split('\n').forEach(line => {
            if (line.trim()) {
                const [username, hash] = line.split(':');
                users[username] = hash;
            }
        });
        return users;
    } catch (error) {
        console.error('Error reading htpasswd file:', error);
        return {};
    }
}

app.all('/', async (req, res) => {
    const forwarded = {
        method: req.header('X-Forwarded-Method') || req.method,
        protocol: req.header('X-Forwarded-Proto') || req.protocol,
        host: req.header('X-Forwarded-Host') || req.get('host'),
        uri: req.header('X-Forwarded-Uri') || req.originalUrl,
        ip: req.header('X-Forwarded-For') || req.ip,
    };

    const url = `${forwarded.protocol}://${forwarded.host}${forwarded.uri}`;

    try {
        // Check if already authenticated
        if (req.cookies[COOKIE_NAME]) {
            const decoded = jwt.verify(req.cookies[COOKIE_NAME], JWT_SECRET);
            if (decoded) {
                return res.sendStatus(200);
            }
        }

        // Handle login
        if (forwarded.method.toUpperCase() === 'POST') {
            const { username, password } = req.body;
            const users = parseHtpasswd();
            
            if (!users[username]) {
                throw new Error('Invalid credentials');
            }

            // Verify password against htpasswd hash
            const [, hash] = users[username].split('$');
            const isValid = await bcrypt.compare(password, users[username]);
            
            if (!isValid) {
                throw new Error('Invalid credentials');
            }

            // Create JWT token
            const expire = Date.now() + (VALIDITY * 1000);
            const token = jwt.sign({ 
                user: username, 
                exp: Math.floor(expire / 1000) 
            }, JWT_SECRET);

            res.cookie(COOKIE_NAME, token, {
                secure: forwarded.protocol === 'https',
                httpOnly: true,
                expires: new Date(expire)
            });

            return res.redirect(url);
        }

        // Show login form
        res.status(401).render('login', { url });

    } catch (error) {
        console.error(error);
        res.clearCookie(COOKIE_NAME);
        res.status(401).render('login', { url, error: error.message });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.sendStatus(200);
});

app.listen(port, () => {
    console.log(`Auth server running on port ${port}`);
    console.log(`Using htpasswd file at: ${HTPASSWD_PATH}`);
});
