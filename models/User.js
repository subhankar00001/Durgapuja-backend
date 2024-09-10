const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String },
  otpExpiresAt: { type: Date },
  postsCount: { type: Number, default: 0 },       // Add default post count
  followersCount: { type: Number, default: 0 },   // Add default follower count
  followingCount: { type: Number, default: 0 },   // Add default following count
});

module.exports = mongoose.model('User', userSchema);
