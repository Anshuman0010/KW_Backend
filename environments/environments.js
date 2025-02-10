const environments = {
  development: {
    port: 3001,
    mongoUri: 'mongodb+srv://sanamsahu2025:1wOCrtZn3vJMJ7w9@cluster0.mr4wz.mongodb.net/KW?retryWrites=true&w=majority&appName=Cluster0',
    jwtSecret: 'your_super_secret_key_here',
    clientUrl: 'http://localhost:5173',
    serverUrl: 'http://localhost:3001',
    apiPaths: {
      base: '/api',
      auth: {
        signup: '/auth/signup',
        login: '/auth/login',
        logout: '/auth/logout',
        verifyEmail: '/auth/verify-email'
      },
      user: {
        profile: '/user/profile'
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
      base: '/api',
      auth: {
        signup: '/auth/signup',
        login: '/auth/login',
        logout: '/auth/logout',
        verifyEmail: '/auth/verify-email'
      },
      user: {
        profile: '/user/profile'
      }
    }
  }
};

const environment = environments[process.env.NODE_ENV || 'development'];

module.exports = environment;
