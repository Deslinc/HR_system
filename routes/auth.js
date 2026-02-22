import { Router } from 'express';
import * as authController from '../controller/auth.js';
import { authenticate, authorize } from '../middleware/auth.js';
import { authLimiter } from '../rateLimiter.js';

const router = Router();

// ─── Public Routes ─────────────────────────────────────────

/**
 * POST /api/v1/auth/register-admin
 * Bootstrap: creates the first admin account.
 * Requires ADMIN_BOOTSTRAP_SECRET in the request body.
 * One-time use — returns 409 if an admin already exists.
 */
router.post('/register-admin', authLimiter, authController.registerAdmin);

/**
 * POST /api/v1/auth/login
 * Authenticate with email + password.
 * Returns: { accessToken } in body + refreshToken as HttpOnly cookie.
 */
router.post('/login', authLimiter, authController.login);

/**
 * POST /api/v1/auth/set-password
 * New user sets their password using the invite token.
 * Body: { inviteToken, password, confirmPassword }
 */
router.post('/set-password', authLimiter, authController.setPassword);

/**
 * POST /api/v1/auth/refresh-token
 * Issues a new access token using the refresh token.
 * Token can come from HttpOnly cookie or request body.
 */
router.post('/refresh-token', authController.refreshToken);

// ─── Protected Routes ──────────────────────────────────────

/**
 * POST /api/v1/auth/logout
 * Invalidates the user's current refresh token.
 */
router.post('/logout', authenticate, authController.logout);

/**
 * GET /api/v1/auth/me
 * Returns the currently authenticated user's profile.
 */
router.get('/me', authenticate, authController.getMe);

/**
 * POST /api/v1/auth/change-password
 * Changes password for authenticated user.
 * Invalidates all existing sessions.
 */
router.post('/change-password', authenticate, authController.changePassword);

// ─── Admin-Only Routes ─────────────────────────────────────

/**
 * POST /api/v1/auth/create-user
 * Admin creates a new user of any role.
 * Returns an invite token/link for the user to set their password.
 */
router.post('/create-user', authenticate, authorize('admin'), authController.createUser);

export default router;