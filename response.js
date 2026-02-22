/**
 * Sends a standardised JSON success response.
 */
export const sendSuccess = (res, { statusCode = 200, message = 'Success', data = null } = {}) => {
  const payload = { success: true, message };
  if (data !== null) payload.data = data;
  return res.status(statusCode).json(payload);
};

/**
 * Sends a standardised JSON error response.
 */
export const sendError = (res, { statusCode = 500, message = 'Internal Server Error', errors = null } = {}) => {
  const payload = { success: false, message };
  if (errors !== null) payload.errors = errors;
  return res.status(statusCode).json(payload);
};