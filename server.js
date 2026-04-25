import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';

// Load .env from project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

import User from './models/User.js';
import { requireAuth } from './middleware/auth.js';
import { notFound, errorHandler } from './middleware/errors.js';
import { ensureSeededGames } from './services/seed.js';
import gamesRouter from './routes/games.js';
import wishlistRouter from './routes/wishlist.js';
import cartRouter from './routes/cart.js';
import libraryRouter from './routes/library.js';
import paymentsRouter from './routes/payments.js';

const app = express();
const PORT = process.env.PORT || 8000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/gstack';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-gstack';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Middleware
app.use(cors({
  origin: CLIENT_URL,
  credentials: true,
}));
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Store APIs
app.use('/games', gamesRouter);
app.use('/wishlist', wishlistRouter);
app.use('/cart', cartRouter);
app.use('/library', libraryRouter);
app.use('/payments', paymentsRouter);

// MongoDB connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('[Backend] ✅ Connected to MongoDB'))
  .catch((err) => console.error('[Backend] ❌ MongoDB error:', err));

// Seed demo catalog if empty
mongoose.connection.once('open', async () => {
  try {
    const result = await ensureSeededGames();
    if (result.seeded) {
      console.log(`[Backend] ✅ Seeded games catalog (${result.count})`);
    }
  } catch (err) {
    console.error('[Backend] ❌ Seed games error:', err);
  }
});

// ───── SIGNUP ─────
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, password, and username are required.' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'User already registered with this email.' });
    }

    // ✅ Create user - DO NOT hash password here!
    // The schema's pre('save') hook handles bcrypt automatically
    const user = new User({ email, username, password });

    // ✅ DEV MODE: Auto-confirm email (no email server locally)
    // In production, you would send an actual confirmation email instead
    const isDev = process.env.NODE_ENV !== 'production';
    if (isDev) {
      user.emailConfirmed = true;
    } else {
      const confirmToken = user.generateConfirmation_token();
      const confirmLink = `${CLIENT_URL}/login?type=signup&token=${confirmToken}`;
      console.log(`[Dev] Confirmation link for ${email}: ${confirmLink}`);
    }

    await user.save();

    if (isDev) {
      // ✅ DEV: Auto sign-in after signup — return JWT immediately
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      console.log(`[Backend] ✅ User registered & auto-confirmed: ${email}`);
      return res.status(201).json({
        user: { id: user._id, email: user.email, username: user.username },
        token
      });
    }

    // Production: require email confirmation
    return res.status(201).json({
      confirmEmail: true,
      email: user.email,
      message: 'Please check your email to confirm your account.'
    });

  } catch (error) {
    console.error('[Backend] Signup Error:', error);

    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email or username already exists.' });
    }
    if (error.name === 'ValidationError') {
      const msgs = Object.values(error.errors).map(e => e.message);
      return res.status(400).json({ error: msgs.join('. ') });
    }

    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ───── CONFIRM EMAIL ─────
app.get('/auth/confirm-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({ error: 'Confirmation token is required.' });
    }

    const user = await User.findByConfirmationToken(token);
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired confirmation link.' });
    }

    user.emailConfirmed = true;
    await user.save(); // pre-save hook clears the token

    // Redirect to frontend with success flag
    return res.redirect(`${CLIENT_URL}/login?type=signup&token=confirmed`);

  } catch (error) {
    console.error('[Backend] Confirm Email Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ───── SIGNIN ─────
app.post('/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // ✅ Select +password to include it for comparison (schema hides it by default)
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }

    // ✅ Check email confirmation status
    if (!user.emailConfirmed) {
      return res.status(403).json({
        error: 'Email not confirmed',
        requiresConfirmation: true,
        email: user.email
      });
    }

    // ✅ Use schema method to compare (bcrypt happens inside comparePassword)
    const validPassword = await user.comparePassword(password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      user: { id: user._id, email: user.email, username: user.username },
      token
    });

  } catch (error) {
    console.error('[Backend] Signin Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ───── GOOGLE SIGN-IN (ID TOKEN) ─────
app.post('/auth/google', async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: 'credential is required' });
    if (!googleClient) return res.status(500).json({ error: 'Google auth is not configured' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload?.email;
    const name = payload?.name || '';

    if (!email) return res.status(400).json({ error: 'Google token missing email' });

    let user = await User.findOne({ email }).select('+password');
    if (!user) {
      const randomPassword = crypto.randomBytes(24).toString('hex');
      const username = (name || email.split('@')[0] || 'gamer').slice(0, 30);
      user = new User({
        email,
        username,
        password: randomPassword,
        emailConfirmed: true,
      });
      await user.save();
    } else if (!user.emailConfirmed) {
      user.emailConfirmed = true;
      await user.save();
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      user: { id: user._id, email: user.email, username: user.username },
      token
    });
  } catch (error) {
    console.error('[Backend] Google Auth Error:', error);
    res.status(400).json({ error: 'Google authentication failed' });
  }
});

// ───── GET CURRENT USER ─────
app.get('/auth/me', requireAuth, async (req, res) => {
  res.json({ user: req.user });
});

// ───── RESEND CONFIRMATION ─────
app.post('/auth/resend-confirmation', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    const user = await User.findOne({ email });
    if (!user || user.emailConfirmed) {
      // Don't reveal account existence
      return res.json({ message: 'If an account exists, a confirmation email has been sent.' });
    }

    const confirmToken = user.generateConfirmation_token();
    await user.save();

    const confirmLink = `${CLIENT_URL}/login?type=signup&token=${confirmToken}`;
    console.log(`[Dev] Resend confirmation link for ${email}: ${confirmLink}`);

    res.json({ message: 'Confirmation email resent. Check your inbox.' });

  } catch (error) {
    console.error('[Backend] Resend Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ───── FORGOT PASSWORD ─────
app.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const user = await User.findOne({ email });
    if (user) {
      const token = user.generateResetPasswordToken();
      await user.save();
      const resetLink = `${CLIENT_URL}/login?type=reset&token=${token}&email=${encodeURIComponent(email)}`;
      console.log(`[Dev] Password reset link for ${email}: ${resetLink}`);
    }
    // Always return success to avoid leaking account existence
    res.json({ message: 'If an account exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('[Backend] Forgot Password Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ───── RESET PASSWORD ─────
app.post('/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and newPassword are required.' });
    if (String(newPassword).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long.' });

    const user = await User.findByResetPasswordToken(token);
    if (!user) return res.status(400).json({ error: 'Invalid or expired reset link.' });

    user.password = newPassword;
    user.reset_password_token = undefined;
    user.reset_password_expires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful. You can now sign in.' });
  } catch (error) {
    console.error('[Backend] Reset Password Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Optional: Helpful root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'G-Stack API',
    status: 'running 🎮',
    endpoints: {
      signup: 'POST /auth/signup',
      signin: 'POST /auth/signin',
      me: 'GET /auth/me',
      confirm: 'GET /auth/confirm-email?token=...'
    },
    frontend: `Open ${CLIENT_URL} for the app`
  });
});

app.use(notFound);
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`[Backend] API Server running on http://localhost:${PORT}`);
});