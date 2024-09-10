// otpUtil.js
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'subhankarsarkar377@gmail.com', // Replace with your email
    pass: 'uxkkfmonjckdfdcj',  // Replace with your email password or app-specific password
  },
});

// Generate OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Send OTP via email
const sendOTPEmail = async (email, otp) => {
  const mailOptions = {
    from: 'subhankarsarkar377@gmail.com',
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Error sending OTP:', error);
  }
};

module.exports = { generateOTP, sendOTPEmail };
