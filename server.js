const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const { generateOTP, sendOTPEmail } = require('./otpUtil');
const User = require('./models/User');

const multer = require('multer');
const path = require('path');

const fs = require('fs');

// Load environment variables
require('dotenv').config();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};

// App initialization
const app = express();
const port =  process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('uploads'));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Set up Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Contact Us Route
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;

  try {
    // Send email to yourself
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: 'New Contact Us Message',
      text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`,
    });

    // Send confirmation email to user
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Thank You for Contacting Us',
      text: `Hi ${name},\n\nThank you for contacting us! We have received your message and will get back to you soon.\n\nBest regards,\nSubhankar Sarkar (Software Developer)`,
    });

    res.status(200).json({ message: 'Emails sent successfully!' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ message: 'Error sending email' });
  }
});

// User Registration Route with OTP
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOTP();
    const otpExpiresAt = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes

    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiresAt
    });

    await newUser.save();

    // Send OTP email
    await sendOTPEmail(email, otp);

    res.status(200).json({ message: 'User registered successfully. Please verify your OTP.' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error });
  }
});

// OTP Verification Route
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    if (user.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

    if (user.otpExpiresAt < Date.now()) return res.status(400).json({ message: 'OTP expired' });

    // OTP verified successfully; generate JWT token
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Clear OTP fields
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error verifying OTP', error });
  }
});

// User Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

// Forgot Password Route (OTP Generation)
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10-minute expiration
    await user.save();

    // Send OTP via email
    await sendOTPEmail(email, otp);
    res.status(200).json({ message: 'OTP sent to email' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending OTP', error });
  }
});

// Reset Password Route
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await User.findOne({ email, otp });
    if (!user || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error });
  }
});

app.use(express.json());  // Middleware for parsing JSON

app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.status(200).json({ name: user.name });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user data', error });
  }
});

// Profile Route
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId).select('name avatar postsCount followersCount followingCount posts');
    if (!user) return res.status(404).send('User not found');
    res.json(user);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads', file.fieldname === 'photo' ? 'photos' : 'videos');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Routes for uploading files
app.post('/upload/photo', upload.single('photo'), (req, res) => {
  res.status(200).json({ message: 'Photo uploaded successfully', path: req.file.path });
});

app.post('/upload/video', upload.single('video'), (req, res) => {
  res.status(200).json({ message: 'Video uploaded successfully', path: req.file.path });
});

// Route to fetch photos
app.get('/uploads/photos', (req, res) => {
  fs.readdir(path.join(__dirname, 'uploads/photos'), (err, files) => {
    if (err) return res.status(500).send('Error reading directory');
    res.json(files);
  });
});

// Route to fetch videos
const videoDirectory = path.join(__dirname, 'uploads/videos');

// Endpoint to get list of video files
app.get('/api/videos', (req, res) => {
  fs.readdir(videoDirectory, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to list video files' });
    }
    const videoUrls = files.map(file => `/uploads/videos/${file}`);
    res.json({ videos: videoUrls });
  });
});

app.use('/uploads/videos', express.static(videoDirectory));

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
