import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import config from '../config/env.js';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from '../utils/token.js';
import logger from '../utils/logger.js';

// ─── Helpers ───────────────────────────────────────────────

/**
 * Generates a cryptographically secure random token
 * and returns both the raw token (to send to user) and its SHA-256 hash
 * (to store in DB — never store raw tokens).
 */
const generateSecureToken = () => {
  const raw = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
};

/**
 * Hashes a refresh token for safe DB storage.
 */
const hashRefreshToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

/**
 * Removes expired refresh tokens from a user's token list.
 */
const pruneExpiredTokens = (tokens) => {
  return tokens.filter((t) => t.expiresAt > new Date());
};

// ─── Service Methods ───────────────────────────────────────

/**
 * Register the very first admin account.
 * Protected by a bootstrap secret from environment variables.
 * After this, admins are created via the normal user management flow.
 */
export const registerAdmin = async ({ firstName, lastName, email, password, bootstrapSecret }) => {
  // Validate the bootstrap secret
  if (bootstrapSecret !== config.admin.bootstrapSecret) {
    throw Object.assign(new Error('Invalid admin bootstrap secret.'), { statusCode: 403 });
  }

  // Prevent creating multiple admins via this route
  const existingAdmin = await User.findOne({ role: 'admin' });
  if (existingAdmin) {
    throw Object.assign(
      new Error('An admin account already exists. Use the standard user management flow to add more admins.'),
      { statusCode: 409 }
    );
  }

  const existingEmail = await User.findOne({ email });
  if (existingEmail) {
    throw Object.assign(new Error('An account with this email already exists.'), { statusCode: 409 });
  }

  const admin = await User.create({
    firstName,
    lastName,
    email,
    password,
    role: 'admin',
    hasSetPassword: true,
  });

  logger.info(`Admin account created: ${admin.email}`);

  return {
    id: admin._id,
    firstName: admin.firstName,
    lastName: admin.lastName,
    email: admin.email,
    role: admin.role,
  };
};

/**
 * Login with email + password.
 * Returns access token and sets refresh token.
 * Handles account locking after repeated failed attempts.
 */
export const login = async ({ email, password }) => {
  // Explicitly select fields excluded by default
  const user = await User.findOne({ email }).select(
    '+password +loginAttempts +lockUntil +refreshTokens +passwordChangedAt'
  );

  if (!user) {
    // Use same error as wrong password to prevent user enumeration
    throw Object.assign(new Error('Invalid email or password.'), { statusCode: 401 });
  }

  if (!user.isActive) {
    throw Object.assign(new Error('Your account has been deactivated. Please contact your administrator.'), { statusCode: 403 });
  }

  if (!user.hasSetPassword) {
    throw Object.assign(new Error('Please set your password using the invite link sent to your email before logging in.'), { statusCode: 403 });
  }

  // Account lockout check
  if (user.isLocked) {
    const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
    throw Object.assign(
      new Error(`Account temporarily locked due to too many failed login attempts. Try again in ${minutesLeft} minute(s).`),
      { statusCode: 423 }
    );
  }

  // Validate password
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    await user.incrementLoginAttempts();
    const attemptsLeft = Math.max(0, 5 - (user.loginAttempts + 1));
    const message =
      attemptsLeft > 0
        ? `Invalid email or password. ${attemptsLeft} attempt(s) remaining before account lock.`
        : 'Invalid email or password. Your account has been temporarily locked.';
    throw Object.assign(new Error(message), { statusCode: 401 });
  }

  // Success — reset failed attempts
  await user.resetLoginAttempts();

  // Issue tokens
  const tokenPayload = { userId: user._id, role: user.role, email: user.email };
  const accessToken = signAccessToken(tokenPayload);
  const refreshToken = signRefreshToken(user._id);

  // Store hashed refresh token (support multiple devices)
  const tokenHash = hashRefreshToken(refreshToken);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const cleanTokens = pruneExpiredTokens(user.refreshTokens);
  cleanTokens.push({ tokenHash, expiresAt });

  // Keep a max of 5 active sessions per user
  const trimmedTokens = cleanTokens.slice(-5);

  await User.updateOne({ _id: user._id }, { $set: { refreshTokens: trimmedTokens } });

  logger.info(`User logged in: ${user.email} [${user.role}]`);

  return {
    accessToken,
    refreshToken,
    user: {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
    },
  };
};

/**
 * Admin creates a new user (any role except admin via this route).
 * Generates a secure invite token and returns it.
 * In production, this token would be emailed to the user.
 */
export const createUser = async ({ firstName, lastName, email, role }, adminId) => {
  const existing = await User.findOne({ email });
  if (existing) {
    throw Object.assign(new Error('A user with this email already exists.'), { statusCode: 409 });
  }

  const { raw: inviteToken, hash: inviteTokenHash } = generateSecureToken();
  const inviteTokenExpires = new Date(
    Date.now() + config.invite.tokenExpiresHours * 60 * 60 * 1000
  );

  const newUser = await User.create({
    firstName,
    lastName,
    email,
    role,
    inviteToken: inviteTokenHash,
    inviteTokenExpires,
    hasSetPassword: false,
    createdBy: adminId,
  });

  logger.info(`User created by admin ${adminId}: ${newUser.email} [${role}]`);

  return {
    user: {
      id: newUser._id,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      role: newUser.role,
    },
    // In production: send this token via email, do not expose in API response
    // Included here for development/testing — remove or guard in production
    inviteToken,
    inviteLink: `/api/v1/auth/set-password?token=${inviteToken}`,
    expiresAt: inviteTokenExpires,
  };
};

/**
 * User sets their password using the invite token from their email.
 * One-time use — clears the token after successful use.
 */
export const setPassword = async ({ inviteToken, password }) => {
  const tokenHash = crypto.createHash('sha256').update(inviteToken).digest('hex');

  const user = await User.findOne({
    inviteToken: tokenHash,
    inviteTokenExpires: { $gt: new Date() },
  }).select('+inviteToken +inviteTokenExpires');

  if (!user) {
    throw Object.assign(
      new Error('Invalid or expired invite token. Please request a new invite from your administrator.'),
      { statusCode: 400 }
    );
  }

  user.password = password;
  user.hasSetPassword = true;
  user.inviteToken = undefined;
  user.inviteTokenExpires = undefined;

  await user.save();

  logger.info(`Password set for user: ${user.email}`);

  return {
    id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
  };
};

/**
 * Issues a new access token using a valid refresh token.
 * Implements refresh token rotation — old token is invalidated.
 */
export const refreshAccessToken = async (incomingRefreshToken) => {
  if (!incomingRefreshToken) {
    throw Object.assign(new Error('Refresh token is required.'), { statusCode: 401 });
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(incomingRefreshToken);
  } catch {
    throw Object.assign(new Error('Invalid or expired refresh token.'), { statusCode: 401 });
  }

  const user = await User.findById(decoded.userId).select('+refreshTokens');
  if (!user) {
    throw Object.assign(new Error('User no longer exists.'), { statusCode: 401 });
  }

  if (!user.isActive) {
    throw Object.assign(new Error('Account is deactivated.'), { statusCode: 403 });
  }

  const incomingHash = hashRefreshToken(incomingRefreshToken);
  const tokenIndex = user.refreshTokens.findIndex((t) => t.tokenHash === incomingHash);

  if (tokenIndex === -1) {
    // Possible token reuse attack — invalidate ALL tokens for this user
    await User.updateOne({ _id: user._id }, { $set: { refreshTokens: [] } });
    logger.warn(`Refresh token reuse detected for user: ${user.email}. All sessions revoked.`);
    throw Object.assign(
      new Error('Session invalid. Please log in again.'),
      { statusCode: 401 }
    );
  }

  // Rotate: remove old token, issue new one
  const newRefreshToken = signRefreshToken(user._id);
  const newHash = hashRefreshToken(newRefreshToken);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const updatedTokens = pruneExpiredTokens(user.refreshTokens);
  updatedTokens.splice(
    updatedTokens.findIndex((t) => t.tokenHash === incomingHash),
    1
  );
  updatedTokens.push({ tokenHash: newHash, expiresAt });

  await User.updateOne({ _id: user._id }, { $set: { refreshTokens: updatedTokens.slice(-5) } });

  const accessToken = signAccessToken({
    userId: user._id,
    role: user.role,
    email: user.email,
  });

  return { accessToken, newRefreshToken };
};

/**
 * Logs out a user by invalidating their refresh token.
 */
export const logout = async (userId, refreshToken) => {
  if (!refreshToken) return;

  const tokenHash = hashRefreshToken(refreshToken);
  await User.updateOne(
    { _id: userId },
    { $pull: { refreshTokens: { tokenHash } } }
  );

  logger.info(`User logged out: ${userId}`);
};

/**
 * Changes password for an authenticated user.
 */
export const changePassword = async (userId, { currentPassword, newPassword }) => {
  const user = await User.findById(userId).select('+password');
  if (!user) {
    throw Object.assign(new Error('User not found.'), { statusCode: 404 });
  }

  const isMatch = await user.comparePassword(currentPassword);
  if (!isMatch) {
    throw Object.assign(new Error('Current password is incorrect.'), { statusCode: 401 });
  }

  user.password = newPassword;
  // Invalidate all existing sessions on password change
  user.refreshTokens = [];
  await user.save();

  logger.info(`Password changed for user: ${user.email}`);
};