// authMiddleware.js

const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load environment variables from .env file

function verifyToken(req, res, next) {
  const token = req.headers.authorization; // Token from the 'Authorization' header

  if (!token) {
    return res.status(401).json({ error: 'Token is missing' });
  }

  const secretKey = process.env.JWT_SECRET_KEY; // Get the secret key from environment variables

  jwt.verify(token, secretKey, (error, decoded) => {
    if (error) {
      return res.status(403).json({ error: 'Token verification failed' });
    } else {
      req.user = decoded; // Store the decoded data in the request object
      next(); // Continue to the next middleware or route handler
    }
  });
}

module.exports = verifyToken;
