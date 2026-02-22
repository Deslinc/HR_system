/**
 * Wraps async route handlers to catch errors and pass them to Express error handler.
 * Eliminates need for try-catch in every controller.
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};