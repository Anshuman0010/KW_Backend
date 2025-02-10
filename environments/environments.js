const environments = {
  development: {
    port: process.env.PORT || 3001,
    mongoUri: process.env.MONGODB_URI || 'mongodb+srv://sanamsahu2025:1wOCrtZn3vJMJ7w9@cluster0.mr4wz.mongodb.net/KW?retryWrites=true&w=majority&appName=Cluster0',
    jwtSecret: process.env.JWT_SECRET || 'your_super_secret_key_here',
    clientUrl: process.env.CLIENT_URL || 'http://localhost:5173',
    serverUrl: process.env.SERVER_URL || 'http://localhost:3001',
    apiPaths: {
      base: process.env.API_BASE_PATH || '/api',
      auth: {
        signup: process.env.AUTH_SIGNUP_PATH || '/auth/signup',
        login: process.env.AUTH_LOGIN_PATH || '/auth/login',
        logout: process.env.AUTH_LOGOUT_PATH || '/auth/logout',
        verifyEmail: process.env.AUTH_VERIFY_EMAIL_PATH || '/auth/verify-email'
      },
      user: {
        profile: process.env.USER_PROFILE_PATH || '/user/profile'
      }
    }
  },
  production: {
    port: process.env.PORT || 3001,
    mongoUri: process.env.MONGODB_URI,
    jwtSecret: process.env.JWT_SECRET,
    clientUrl: process.env.CLIENT_URL || 'https://kiitwallah.com',
    serverUrl: process.env.SERVER_URL || 'https://api.kiitwallah.com',
    apiPaths: {
      base: process.env.API_BASE_PATH || '/api',
      auth: {
        signup: process.env.AUTH_SIGNUP_PATH || '/auth/signup',
        login: process.env.AUTH_LOGIN_PATH || '/auth/login',
        logout: process.env.AUTH_LOGOUT_PATH || '/auth/logout',
        verifyEmail: process.env.AUTH_VERIFY_EMAIL_PATH || '/auth/verify-email'
      },
      user: {
        profile: process.env.USER_PROFILE_PATH || '/user/profile'
      }
    }
  }
};

// Validate required environment variables
const validateEnv = () => {
  const requiredVars = [
    'MONGODB_URI',
    'JWT_SECRET'
  ];

  const missingVars = requiredVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }
};

// Only validate in production
if (process.env.NODE_ENV === 'production') {
  validateEnv();
}

const environment = environments[process.env.NODE_ENV || 'development'];

// Log configuration (excluding sensitive data)
console.log('🔧 Environment Configuration:', {
  NODE_ENV: process.env.NODE_ENV || 'development',
  port: environment.port,
  clientUrl: environment.clientUrl,
  serverUrl: environment.serverUrl,
  apiPaths: environment.apiPaths
});

module.exports = environment;
