import * as authService from '../AuthService.js';
import { sendSuccess, sendError } from '../response.js';
import { attachRefreshCookie, clearRefreshCookie } from '../token.js';
import {
  adminRegisterSchema,
  loginSchema,
  createUserSchema,
  setPasswordSchema,
  changePasswordSchema,
} from '../validator/auth.js';
import logger from '../logger.js';
import { asyncHandler } from '../asynchandler.js';

// ─── Admin Registration (Bootstrap) ──────────────────────

export const registerAdmin = asyncHandler(async (req, res) => {
  const { error, value } = adminRegisterSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  const admin = await authService.registerAdmin(value);
  return sendSuccess(res, {
    statusCode: 201,
    message: 'Admin account created successfully.',
    data: admin,
  });
});

// ─── Login ────────────────────────────────────────────────

export const login = asyncHandler(async (req, res) => {
  const { error, value } = loginSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  const { accessToken, refreshToken, user } = await authService.login(value);

  attachRefreshCookie(res, refreshToken);

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Login successful.',
    data: { accessToken, user },
  });
});

// ─── Create User (Admin only) ─────────────────────────────

export const createUser = asyncHandler(async (req, res) => {
  const { error, value } = createUserSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  const result = await authService.createUser(value, req.user.userId);
  return sendSuccess(res, {
    statusCode: 201,
    message: `User created. An invite link has been generated. Share it with ${result.user.email}.`,
    data: result,
  });
});

// ─── Set Password (from invite link) ─────────────────────

export const setPassword = asyncHandler(async (req, res) => {
  const { error, value } = setPasswordSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  const user = await authService.setPassword(value);
  return sendSuccess(res, {
    statusCode: 200,
    message: 'Password set successfully. You can now log in.',
    data: user,
  });
});

// ─── Refresh Access Token ──────────────────────────────────

export const refreshToken = asyncHandler(async (req, res) => {
  // Prefer HttpOnly cookie; fall back to body for non-browser clients
  const incomingToken = req.cookies?.refreshToken || req.body?.refreshToken;

  const { accessToken, newRefreshToken } = await authService.refreshAccessToken(incomingToken);

  attachRefreshCookie(res, newRefreshToken);

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Access token refreshed.',
    data: { accessToken },
  });
});

// ─── Logout ────────────────────────────────────────────────

export const logout = asyncHandler(async (req, res) => {
  const refreshTokenValue = req.cookies?.refreshToken || req.body?.refreshToken;

  await authService.logout(req.user.userId, refreshTokenValue);
  clearRefreshCookie(res);
  return sendSuccess(res, { statusCode: 200, message: 'Logged out successfully.' });
});

// ─── Change Password ───────────────────────────────────────

export const changePassword = asyncHandler(async (req, res) => {
  const { error, value } = changePasswordSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return sendError(res, {
      statusCode: 422,
      message: 'Validation failed',
      errors: error.details.map((d) => d.message),
    });
  }

  await authService.changePassword(req.user.userId, value);
  clearRefreshCookie(res);
  return sendSuccess(res, {
    statusCode: 200,
    message: 'Password changed successfully. Please log in again.',
  });
});

// ─── Get Current User (me) ────────────────────────────────

export const getMe = asyncHandler(async (req, res) => {
  const User = (await import('../user.js')).default;
  const user = await User.findById(req.user.userId);
  
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
});