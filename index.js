const express = require('express');
const cors = require('cors');
const https = require('https');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const env = require('./environments/environments');

const User = require('./models/User');

const app = express();

// Enable CORS for your frontend domain
app.use(cors({
  origin: '*',
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Test API endpoint
app.get('/test', (req, res) => {
  res.json({ 
    status: 'success',
    message: 'API is working!',
    timestamp: new Date(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Connect to MongoDB
mongoose.connect(env.mongoUri)
  .then(() => console.log('🚀 Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Blacklist for storing invalidated tokens
const tokenBlacklist = new Set();

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ message: 'Token has been invalidated' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Server is running' });
});

// Email verification endpoint
app.post(`${env.apiPaths.base}/auth/verify-email`, (req, res) => {
  const { user_json_url } = req.body;

  if (!user_json_url) {
    return res.status(400).json({ error: "Missing user_json_url" });
  }

  https.get(user_json_url, (response) => {
    let data = "";

    response.on("data", (chunk) => {
      data += chunk;
    });

    response.on("end", () => {
      try {
        const jsonData = JSON.parse(data);
        const user_email_id = jsonData.user_email_id;

        console.log("✅ Verified Email:", user_email_id);
        res.json({ email: user_email_id });
      } catch (error) {
        console.error("❌ JSON Parse Error:", error);
        res.status(500).json({ error: "Invalid response from email verification service" });
      }
    });
  }).on("error", (err) => {
    console.error("❌ HTTP Request Error:", err.message);
    res.status(500).json({ error: "Failed to fetch email" });
  });
});

// Signup endpoint
app.post(`${env.apiPaths.base}/auth/signup`, async (req, res) => {
  try {
    const { name, email, password, rollNumber } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { rollNumber }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        message: existingUser.email === email ? 
          'Email already registered' : 
          'Roll number already registered' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      name,
      email,
      rollNumber,
      password: hashedPassword,
      isVerified: true // Since email is already verified
    });

    await user.save();

    res.status(201).json({ 
      message: 'Account created successfully',
      user: {
        name: user.name,
        email: user.email,
        rollNumber: user.rollNumber
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post(`${env.apiPaths.base}/auth/login`, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        name: user.name,
        rollNumber: user.rollNumber
      },
      env.jwtSecret,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        rollNumber: user.rollNumber
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Example of a protected route
app.get(`${env.apiPaths.base}/user/profile`, verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout endpoint
app.post(`${env.apiPaths.base}/auth/logout`, verifyToken, (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    tokenBlacklist.add(token);
  }
  res.json({ message: 'Logged out successfully' });
});

const PORT = env.port;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({ message: 'Internal server error' });
}); 