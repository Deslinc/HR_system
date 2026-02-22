import * as authService from '../AuthService.js';
import { sendSuccess, sendError } from '../response.js';
import { attachRefreshCookie, clearRefreshCookie } from '..token.js';
import {
  adminRegisterSchema,
  loginSchema,
  createUserSchema,
  setPasswordSchema,
  changePasswordSchema,
} from '../validator/auth.js';
import logger from '../logger.js';

// ─── Admin Registration (Bootstrap) ──────────────────────

export const registerAdmin = async (req, res) => {
  const { error, value } = adminRegisterSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  try {
    const admin = await authService.registerAdmin(value);
    return sendSuccess(res, {
      statusCode: 201,
      message: 'Admin account created successfully.',
      data: admin,
    });
  } catch (err) {
    logger.error(`registerAdmin error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Login ────────────────────────────────────────────────

export const login = async (req, res) => {
  const { error, value } = loginSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  try {
    const { accessToken, refreshToken, user } = await authService.login(value);

    attachRefreshCookie(res, refreshToken);

    return sendSuccess(res, {
      statusCode: 200,
      message: 'Login successful.',
      data: { accessToken, user },
    });
  } catch (err) {
    logger.error(`login error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Create User (Admin only) ─────────────────────────────

export const createUser = async (req, res) => {
  const { error, value } = createUserSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  try {
    const result = await authService.createUser(value, req.user.userId);
    return sendSuccess(res, {
      statusCode: 201,
      message: `User created. An invite link has been generated. Share it with ${result.user.email}.`,
      data: result,
    });
  } catch (err) {
    logger.error(`createUser error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Set Password (from invite link) ─────────────────────

export const setPassword = async (req, res) => {
  const { error, value } = setPasswordSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  try {
    const user = await authService.setPassword(value);
    return sendSuccess(res, {
      statusCode: 200,
      message: 'Password set successfully. You can now log in.',
      data: user,
    });
  } catch (err) {
    logger.error(`setPassword error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Refresh Access Token ──────────────────────────────────

export const refreshToken = async (req, res) => {
  // Prefer HttpOnly cookie; fall back to body for non-browser clients
  const incomingToken = req.cookies?.refreshToken || req.body?.refreshToken;

  try {
    const { accessToken, newRefreshToken } = await authService.refreshAccessToken(incomingToken);

    attachRefreshCookie(res, newRefreshToken);

    return sendSuccess(res, {
      statusCode: 200,
      message: 'Access token refreshed.',
      data: { accessToken },
    });
  } catch (err) {
    clearRefreshCookie(res);
    logger.error(`refreshToken error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 401, message: err.message });
  }
};

// ─── Logout ────────────────────────────────────────────────

export const logout = async (req, res) => {
  const refreshTokenValue = req.cookies?.refreshToken || req.body?.refreshToken;

  try {
    await authService.logout(req.user.userId, refreshTokenValue);
    clearRefreshCookie(res);
    return sendSuccess(res, { statusCode: 200, message: 'Logged out successfully.' });
  } catch (err) {
    logger.error(`logout error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Change Password ───────────────────────────────────────

export const changePassword = async (req, res) => {
  const { error, value } = changePasswordSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  try {
    await authService.changePassword(req.user.userId, value);
    clearRefreshCookie(res);
    return sendSuccess(res, {
      statusCode: 200,
      message: 'Password changed successfully. Please log in again.',
    });
  } catch (err) {
    logger.error(`changePassword error: ${err.message}`);
    return sendError(res, { statusCode: err.statusCode || 500, message: err.message });
  }
};

// ─── Get Current User (me) ────────────────────────────────

export const getMe = async (req, res) => {
  try {
    const user = await (await import('../models/User.js')).default.findById(req.user.userId);
    if (!user) {
      return sendError(res, { statusCode: 404, message: 'User not found.' });
    }
    return sendSuccess(res, {
      statusCode: 200,
      message: 'Authenticated user retrieved.',
      data: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    logger.error(`getMe error: ${err.message}`);
    return sendError(res, { statusCode: 500, message: 'Could not retrieve user profile.' });
  }
};