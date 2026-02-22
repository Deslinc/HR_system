import { verifyAccessToken } from '../token.js';
import { sendError } from '../response.js';

/**
 * Protects routes — verifies the Bearer access token.
 * Attaches decoded payload to req.user on success.
 */
export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendError(res, {
      statusCode: 401,
      message: 'Access token is missing or malformed. Expected: Authorization: Bearer <token>',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded; // { userId, role, email }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return sendError(res, {
        statusCode: 401,
        message: 'Access token has expired. Please refresh your token.',
      });
    }
    return sendError(res, {
      statusCode: 401,
      message: 'Invalid access token.',
    });
  }
};

/**
 * Role-based access control middleware factory.
 * Usage: authorize('admin', 'hr_manager')
 */
export const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return sendError(res, { statusCode: 401, message: 'Not authenticated.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return sendError(res, {
        statusCode: 403,
        message: `Access denied. Required role(s): ${allowedRoles.join(', ')}.`,
      });
    }

    next();
  };
};