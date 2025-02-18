const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const path = require('path');

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

// Function to verify credentials against Easypanel Basic Auth
async function verifyCredentials(username, password, verifyUrl) {
    try {
        console.log(`Verifying credentials for user ${username} against ${verifyUrl}`);
        const auth = Buffer.from(`${username}:${password}`).toString('base64');
        const response = await fetch(verifyUrl, {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });
        console.log(`Verification response status: ${response.status}`);
        return response.status === 200;
    } catch (error) {
        console.error('Error verifying credentials:', error);
        return false;
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

    // Log headers for debugging
    console.log('Forwarded headers:', {
        method: forwarded.method,
        protocol: forwarded.protocol,
        host: forwarded.host,
        uri: forwarded.uri
    });

    const originalUrl = `${forwarded.protocol}://${forwarded.host}${forwarded.uri}`;
    
    try {
        // Check if already authenticated
        if (req.cookies[COOKIE_NAME]) {
            const decoded = jwt.verify(req.cookies[COOKIE_NAME], JWT_SECRET);
            if (decoded && decoded.host === forwarded.host) {
                // Add Basic Auth header to the response for downstream services
                const auth = Buffer.from(`${decoded.user}:${decoded.pass}`).toString('base64');
                res.setHeader('Authorization', `Basic ${auth}`);
                return res.sendStatus(200);
            }
        }

        // Handle login
        if (forwarded.method.toUpperCase() === 'POST') {
            const { username, password } = req.body;
            
            // Verify against the original requesting host
            const verifyUrl = `${forwarded.protocol}://${forwarded.host}`;
            console.log(`Attempting to verify against: ${verifyUrl}`);
            
            const isValid = await verifyCredentials(username, password, verifyUrl);
            
            if (!isValid) {
                throw new Error('Invalid credentials');
            }

            // Create JWT token
            const expire = Date.now() + (VALIDITY * 1000);
            const token = jwt.sign({ 
                user: username,
                pass: password,
                host: forwarded.host,
                exp: Math.floor(expire / 1000) 
            }, JWT_SECRET);

            res.cookie(COOKIE_NAME, token, {
                secure: forwarded.protocol === 'https',
                httpOnly: true,
                expires: new Date(expire),
                domain: process.env.COOKIE_DOMAIN || undefined
            });

            return res.redirect(originalUrl);
        }

        // Show login form with the original requesting host
        const targetHost = forwarded.host;
        console.log(`Rendering login form for host: ${targetHost}`);
        
        res.status(401).render('login', { 
            url: originalUrl,
            host: targetHost
        });

    } catch (error) {
        console.error('Error in request handling:', error);
        res.clearCookie(COOKIE_NAME);
        res.status(401).render('login', { 
            url: originalUrl, 
            host: forwarded.host,
            error: error.message 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.sendStatus(200);
});

app.listen(port, () => {
    console.log(`Auth server running on port ${port}`);
});
