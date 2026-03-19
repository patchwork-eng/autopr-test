// Authentication utilities
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

class AuthService {
  constructor(secret, tokenExpiry = '24h') {
    this.secret = secret;
    this.tokenExpiry = tokenExpiry;
    this.saltRounds = 10;
  }

  async hashPassword(password) {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  generateToken(userId, roles = []) {
    return jwt.sign({ userId, roles }, this.secret, { expiresIn: this.tokenExpiry });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.secret);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw new Error('Session expired. Please log in again.');
      }
      throw new Error('Invalid token.');
    }
  }

  async refreshToken(oldToken) {
    const decoded = this.verifyToken(oldToken);
    // Remove exp and iat before re-signing
    const { exp, iat, ...payload } = decoded;
    return this.generateToken(payload.userId, payload.roles);
  }
}

module.exports = AuthService;