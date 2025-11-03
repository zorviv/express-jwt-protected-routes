const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware to parse JSON
app.use(express.json());

// Secret key for JWT (in production, use environment variables)
const SECRET_KEY = 'your-secret-key-here';

// Hardcoded user credentials for demo purposes
const USERS = [
  { id: 1, username: 'admin', password: 'admin123' },
  { id: 2, username: 'user', password: 'user123' }
];

// JWT verification middleware
const verifyToken = (req, res, next) => {
  // Get the authorization header
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // Check if it's a Bearer token
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  
  if (!token) {
    return res.status(401).json({ error: 'Invalid token format' });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Public route - Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Find user
  const user = USERS.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign(
    { id: user.id, username: user.username },
    SECRET_KEY,
    { expiresIn: '1h' }
  );

  res.json({
    message: 'Login successful',
    token: token,
    user: { id: user.id, username: user.username }
  });
});

// Public route - Home
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the JWT Protected API' });
});

// Protected route - Dashboard
app.get('/dashboard', verifyToken, (req, res) => {
  res.json({
    message: 'Welcome to your dashboard',
    user: req.user
  });
});

// Protected route - User profile
app.get('/profile', verifyToken, (req, res) => {
  res.json({
    message: 'User profile data',
    user: req.user,
    additionalInfo: 'This is protected user information'
  });
});

// Protected route - Admin data
app.get('/admin', verifyToken, (req, res) => {
  // Additional authorization check (optional)
  if (req.user.username !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admin only.' });
  }
  
  res.json({
    message: 'Admin data',
    user: req.user,
    adminData: 'Sensitive admin information'
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log('\nAvailable endpoints:');
  console.log('POST /login - Login to get JWT token');
  console.log('GET / - Public home route');
  console.log('GET /dashboard - Protected dashboard (requires valid JWT)');
  console.log('GET /profile - Protected profile (requires valid JWT)');
  console.log('GET /admin - Protected admin route (requires valid JWT + admin user)');
  console.log('\nTest credentials:');
  console.log('Username: admin, Password: admin123');
  console.log('Username: user, Password: user123');
});

module.exports = app;
