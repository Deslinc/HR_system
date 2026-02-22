import jwt from 'jsonwebtoken';
import config from '../config/env.js';

/**
 * Signs a short-lived access token.
 * Payload contains userId, role, and email.
 */
export const signAccessToken = (payload) => {
  return jwt.sign(payload, config.jwt.accessSecret, {
    expiresIn: config.jwt.accessExpiresIn,
    issuer: 'teamhabour-api',
    audience: 'teamhabour-client',
  });
};

/**
 * Signs a long-lived refresh token.
 * Only embeds userId to minimise surface area.
 */
export const signRefreshToken = (userId) => {
  return jwt.sign({ userId }, config.jwt.refreshSecret, {
    expiresIn: config.jwt.refreshExpiresIn,
    issuer: 'teamhabour-api',
    audience: 'teamhabour-client',
  });
};

/**
 * Verifies an access token. Throws if invalid or expired.
 */
export const verifyAccessToken = (token) => {
  return jwt.verify(token, config.jwt.accessSecret, {
    issuer: 'teamhabour-api',
    audience: 'teamhabour-client',
  });
};

/**
 * Verifies a refresh token. Throws if invalid or expired.
 */
export const verifyRefreshToken = (token) => {
  return jwt.verify(token, config.jwt.refreshSecret, {
    issuer: 'teamhabour-api',
    audience: 'teamhabour-client',
  });
};

/**
 * Attaches the refresh token as an httpOnly secure cookie.
 */
export const attachRefreshCookie = (res, refreshToken) => {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  });
};

/**
 * Clears the refresh token cookie.
 */
export const clearRefreshCookie = (res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: 'strict',
  });
};