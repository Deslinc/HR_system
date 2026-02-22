import app from './app.js';
import config from './env.js';
import connectDB from './database.js';
import logger from './logger.js';

const startServer = async () => {
  // Connect to MongoDB first
  await connectDB();

  const server = app.listen(config.port, () => {
    logger.info(`HR and PayRole system API running in ${config.env} mode on port ${config.port}`);
  });

  // ─── Graceful Shutdown ─────────────────────────────────
  const gracefulShutdown = (signal) => {
    logger.info(`${signal} received. Shutting down gracefully...`);
    server.close(() => {
      logger.info('HTTP server closed.');
      process.exit(0);
    });

    // Force exit after 10s if something hangs
    setTimeout(() => {
      logger.error('Forced shutdown after timeout.');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  // Catch unhandled promise rejections
  process.on('unhandledRejection', (reason) => {
    logger.error(`Unhandled Rejection: ${reason}`);
    gracefulShutdown('unhandledRejection');
  });
};

startServer();