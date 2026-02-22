import rateLimit from 'express-rate-limit';
import { sendError } from './response.js';

const rateLimitHandler = (req, res) => {
  return sendError(res, {
    statusCode: 429,
    message: 'Too many requests. Please slow down and try again later.',
  });
};

/**
 * Strict limiter for sensitive auth endpoints (login, set-password).
 * 10 requests per 15 minutes per IP.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

/**
 * General API limiter.
 * 100 requests per 15 minutes per IP.
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});