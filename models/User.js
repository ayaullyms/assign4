// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  failedAttempts: { type: Number, default: 0 },
  isLocked: { type: Boolean, default: false }
});

module.exports = mongoose.model('User', UserSchema);