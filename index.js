const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const path = require('path');
const url = require('url');

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

// Function to get service name from host
function getServiceName(host) {
    // Extract service name from subdomain
    const serviceName = host.split('.')[0];
    console.log(`Extracted service name: ${serviceName} from host: ${host}`);
    return serviceName;
}

// Function to verify credentials against Easypanel Basic Auth
async function verifyCredentials(username, password, serviceName) {
    try {
        // Use internal Docker service name for verification
        const verifyUrl = `http://${serviceName}`;
        console.log(`Verifying credentials for user ${username} against service: ${serviceName} (${verifyUrl})`);
        
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

    console.log('Request headers:', {
        'X-Forwarded-Host': req.header('X-Forwarded-Host'),
        'Host': req.get('host'),
        ...forwarded
    });

    const originalUrl = `${forwarded.protocol}://${forwarded.host}${forwarded.uri}`;
    const serviceName = getServiceName(forwarded.host);
    
    try {
        // Check if already authenticated
        if (req.cookies[COOKIE_NAME]) {
            const decoded = jwt.verify(req.cookies[COOKIE_NAME], JWT_SECRET);
            if (decoded && decoded.service === serviceName) {
                // Add Basic Auth header to the response for downstream services
                const auth = Buffer.from(`${decoded.user}:${decoded.pass}`).toString('base64');
                res.setHeader('Authorization', `Basic ${auth}`);
                return res.sendStatus(200);
            }
        }

        // Handle login
        if (forwarded.method.toUpperCase() === 'POST') {
            const { username, password } = req.body;
            
            const isValid = await verifyCredentials(username, password, serviceName);
            
            if (!isValid) {
                throw new Error('Invalid credentials');
            }

            // Create JWT token
            const expire = Date.now() + (VALIDITY * 1000);
            const token = jwt.sign({ 
                user: username,
                pass: password,
                service: serviceName,
                exp: Math.floor(expire / 1000) 
            }, JWT_SECRET);

            res.cookie(COOKIE_NAME, token, {
                secure: forwarded.protocol === 'https',
                httpOnly: true,
                expires: new Date(expire)
            });

            return res.redirect(originalUrl);
        }

        // Show login form
        console.log(`Rendering login form for service: ${serviceName}`);
        
        res.status(401).render('login', { 
            url: originalUrl,
            host: forwarded.host,
            service: serviceName
        });

    } catch (error) {
        console.error('Error in request handling:', error);
        res.clearCookie(COOKIE_NAME);
        res.status(401).render('login', { 
            url: originalUrl, 
            host: forwarded.host,
            service: serviceName,
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
