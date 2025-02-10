const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  rollNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    uppercase: true
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  lastLogin: {
    type: Date
  },
  profilePicture: {
    type: String,
    default: ''
  },
  bio: {
    type: String,
    default: ''
  },
  branch: {
    type: String,
    trim: true
  },
  graduationYear: {
    type: Number
  },
  skills: [{
    type: String,
    trim: true
  }],
  socialLinks: {
    linkedin: String,
    github: String,
    portfolio: String
  }
});

// Add any pre-save hooks or methods here
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    // Password hashing will be added here
  }
  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User; 