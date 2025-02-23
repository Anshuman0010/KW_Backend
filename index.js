const express = require('express');
const cors = require('cors');
const https = require('https');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const env = require('./environments/environments');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const User = require('./models/User');
const Admin = require('./models/Admin');
const Alumni = require('./models/Alumni');

const app = express();

// Move this line before all routes and update the path
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir, { recursive: true });
}

// Update the static file serving path
app.use('/assets', express.static(assetsDir));

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

// Middleware to verify admin token
const verifyAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, env.jwtSecret);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized as admin' });
    }

    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      return res.status(401).json({ message: 'Admin not found' });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin verification error:', error);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

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

// Log incoming requests
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path}`);
  next();
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

// Admin routes
app.post(`${env.apiPaths.base}/auth/admin/signup`, async (req, res) => {
  try {
    console.log('📝 Admin signup attempt:', req.body.email);
    const { email, password } = req.body;
    
    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ message: 'Admin already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new admin
    const admin = new Admin({
      email,
      password: hashedPassword,
      createdAt: new Date()
    });

    await admin.save();
    res.status(201).json({ message: 'Admin created successfully' });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Login
app.post(`${env.apiPaths.base}/auth/admin/login`, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: admin._id,
        email: admin.email,
        role: 'admin'
      },
      env.jwtSecret,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      admin: {
        id: admin._id,
        email: admin.email
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify Admin Token with proper authentication
app.get(`${env.apiPaths.base}/auth/admin/verify`, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, env.jwtSecret);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized as admin' });
    }

    const admin = await Admin.findById(decoded.id).select('-password');
    if (!admin) {
      return res.status(401).json({ message: 'Admin not found' });
    }

    res.json({ 
      message: 'Admin verified',
      admin: {
        id: admin._id,
        email: admin.email
      }
    });
  } catch (error) {
    console.error('Admin verification error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Alumni routes
app.get(`${env.apiPaths.base}/admin/alumni`, verifyAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;

    const [alumni, total] = await Promise.all([
      Alumni.find()
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Alumni.countDocuments()
    ]);

    res.json({
      alumni,
      total,
      page,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Error fetching alumni:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post(`${env.apiPaths.base}/admin/alumni`, verifyAdmin, async (req, res) => {
  try {
    const alumni = new Alumni(req.body);
    await alumni.save();
    res.status(201).json(alumni);
  } catch (error) {
    console.error('Error creating alumni:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Public Alumni routes
app.get(`${env.apiPaths.base}/alumni`, async (req, res) => {
  try {
    const alumni = await Alumni.find({ isActive: true }).sort({ rating: -1 });
    res.json(alumni);
  } catch (error) {
    console.error('Error fetching alumni:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update alumni
app.put(`${env.apiPaths.base}/admin/alumni/:id`, verifyAdmin, async (req, res) => {
  try {
    const alumni = await Alumni.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updatedAt: Date.now() },
      { new: true }
    );
    if (!alumni) {
      return res.status(404).json({ message: 'Alumni not found' });
    }
    res.json(alumni);
  } catch (error) {
    console.error('Error updating alumni:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete alumni
app.delete(`${env.apiPaths.base}/admin/alumni/:id`, verifyAdmin, async (req, res) => {
  try {
    const alumni = await Alumni.findByIdAndDelete(req.params.id);
    if (!alumni) {
      return res.status(404).json({ message: 'Alumni not found' });
    }
    res.json({ message: 'Alumni deleted successfully' });
  } catch (error) {
    console.error('Error deleting alumni:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Configure multer for PDF storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, assetsDir); // Use the absolute path
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeFileName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${uniqueSuffix}-${safeFileName}`);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed!'), false);
    }
  },
  limits: {
    fileSize: 25 * 1024 * 1024 // Increased to 25MB limit
  }
});

// Add error handling middleware for Multer errors
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        message: 'File is too large. Maximum size is 25MB' 
      });
    }
    return res.status(400).json({ 
      message: `Upload error: ${err.message}` 
    });
  }
  next(err);
};

// Create Resource model
const resourceSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  filepath: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

const Resource = mongoose.model('Resource', resourceSchema);

// Resource routes with error handling
app.post(
  `${env.apiPaths.base}${env.apiPaths.admin.resources}`, 
  verifyAdmin,
  (req, res, next) => {
    upload.single('pdf')(req, res, (err) => {
      if (err) {
        handleMulterError(err, req, res, next);
      } else {
        next();
      }
    });
  },
  async (req, res) => {
    try {
      const { title, description } = req.body;
      const file = req.file;

      if (!file) {
        return res.status(400).json({ message: 'No PDF file uploaded' });
      }

      const resource = new Resource({
        title,
        description,
        filename: file.filename,
        originalName: file.originalname,
        filepath: file.path,
        uploadedBy: req.admin._id
      });

      await resource.save();
      res.status(201).json(resource);
    } catch (error) {
      console.error('Error uploading resource:', error);
      res.status(500).json({ message: 'Error uploading resource' });
    }
  }
);

app.get(`${env.apiPaths.base}${env.apiPaths.admin.resources}`, verifyAdmin, async (req, res) => {
  try {
    const resources = await Resource.find().sort({ uploadedAt: -1 });
    res.json(resources);
  } catch (error) {
    console.error('Error fetching resources:', error);
    res.status(500).json({ message: 'Error fetching resources' });
  }
});

app.delete(`${env.apiPaths.base}${env.apiPaths.admin.resources}/:id`, verifyAdmin, async (req, res) => {
  try {
    const resource = await Resource.findById(req.params.id);
    if (!resource) {
      return res.status(404).json({ message: 'Resource not found' });
    }

    // Delete file from assets folder
    fs.unlinkSync(resource.filepath);
    await Resource.findByIdAndDelete(req.params.id);

    res.json({ message: 'Resource deleted successfully' });
  } catch (error) {
    console.error('Error deleting resource:', error);
    res.status(500).json({ message: 'Error deleting resource' });
  }
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