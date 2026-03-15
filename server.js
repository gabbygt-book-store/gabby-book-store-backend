// backend/server.js - SECURE BACKEND FOR GABBY'S BOOK STORE
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['https://your-vercel-domain.vercel.app', 'http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many payment attempts'
});

app.use(limiter);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://user:pass@cluster.mongodb.net/gabby-book-store', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Schemas
const CustomerSchema = new mongoose.Schema({
  customerId: { type: String, unique: true, required: true },
  phone: { type: String, required: true },
  paymentMethod: { type: String, enum: ['mtn', 'airtel'], required: true },
  purchaseDate: { type: Date, default: Date.now },
  expiryDate: { type: Date, required: true },
  amount: { type: Number, default: 450 },
  transactionId: { type: String, unique: true, required: true },
  status: { type: String, enum: ['confirmed', 'pending', 'failed'], default: 'confirmed' },
  ipAddress: String,
  userAgent: String,
  renewalCount: { type: Number, default: 0 }
}, { timestamps: true });

const AuditLogSchema = new mongoose.Schema({
  adminAction: String,
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
  ipAddress: String
});

const AdminSchema = new mongoose.Schema({
  password: String,
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 }
});

const Customer = mongoose.model('Customer', CustomerSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Utility functions
const hashPhone = (phone) => bcrypt.hashSync(phone, 10);
const encryptPhone = (phone) => Buffer.from(phone).toString('base64');
const decryptPhone = (encrypted) => Buffer.from(encrypted, 'base64').toString('utf-8');
const generateToken = () => jwt.sign({ admin: true }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '2h' });
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
  } catch (error) {
    return null;
  }
};
const getClientIP = (req) => req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

// Auth middleware
const authAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const verified = verifyToken(token);
  if (!verified) return res.status(401).json({ error: 'Invalid token' });
  next();
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Payment initiation
app.post('/api/payment/initiate', paymentLimiter, async (req, res) => {
  try {
    const { phone, method, amount } = req.body;

    if (!phone || !method || !amount) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    if (amount !== 450) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    if (!['mtn', 'airtel'].includes(method)) {
      return res.status(400).json({ error: 'Invalid method' });
    }

    const cleanPhone = phone.replace(/\D/g, '');
    if (cleanPhone.length < 10) {
      return res.status(400).json({ error: 'Invalid phone' });
    }

    const transactionId = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9);

    const customer = new Customer({
      customerId: hashPhone(phone),
      phone: encryptPhone(phone),
      paymentMethod: method,
      amount: amount,
      transactionId: transactionId,
      status: 'confirmed',
      ipAddress: getClientIP(req),
      userAgent: req.headers['user-agent'],
      expiryDate: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000)
    });

    await customer.save();

    await AuditLog.create({
      adminAction: 'PAYMENT_INITIATED',
      details: { transactionId, method, amount },
      ipAddress: getClientIP(req)
    });

    res.json({
      success: true,
      transactionId: transactionId,
      message: 'Payment initiated',
      account: method === 'mtn' ? '0967505014' : '0975622778'
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Payment failed' });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body;
    const adminPassword = process.env.ADMIN_PASSWORD || 'defaultpassword123';

    if (password !== adminPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = generateToken();

    await AuditLog.create({
      adminAction: 'ADMIN_LOGIN',
      details: { success: true },
      ipAddress: getClientIP(req)
    });

    res.json({ success: true, token: token });

  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin stats
app.get('/api/admin/stats', authAdmin, async (req, res) => {
  try {
    const totalSales = await Customer.countDocuments({ status: 'confirmed' });
    const totalRevenue = totalSales * 450;
    const activeUsers = await Customer.countDocuments({
      status: 'confirmed',
      expiryDate: { $gt: new Date() }
    });
    const totalCustomers = await Customer.countDocuments();
    
    const salesByMethod = await Customer.aggregate([
      { $match: { status: 'confirmed' } },
      { $group: {
        _id: '$paymentMethod',
        count: { $sum: 1 }
      }}
    ]);

    const recentTransactions = await Customer.find({ status: 'confirmed' })
      .sort({ createdAt: -1 })
      .limit(10)
      .select('phone paymentMethod amount createdAt')
      .lean();

    const safeTransactions = recentTransactions.map(t => ({
      date: t.createdAt,
      phone: '****' + decryptPhone(t.phone).slice(-4),
      method: t.paymentMethod,
      amount: t.amount
    }));

    res.json({
      totalSales,
      totalRevenue,
      activeUsers,
      totalCustomers,
      salesByPaymentMethod: {
        mtn: salesByMethod.find(m => m._id === 'mtn')?.count || 0,
        airtel: salesByMethod.find(m => m._id === 'airtel')?.count || 0
      },
      recentTransactions: safeTransactions
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Server error' });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`GABBY's Book Store API running on port ${PORT}`);
});

module.exports = app;
