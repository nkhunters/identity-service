import mongoose from 'mongoose';
import { env } from './env';
import { logger } from '../utils/logger';

export async function connectDatabase(): Promise<void> {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(env.MONGODB_URI);
      logger.info('MongoDB connected successfully');
      return;
    } catch (error) {
      retries++;
      logger.error({ error, attempt: retries }, 'MongoDB connection failed');

      if (retries >= maxRetries) {
        logger.fatal('Max retries reached. Exiting...');
        process.exit(1);
      }

      // Exponential backoff
      const delay = Math.min(1000 * Math.pow(2, retries), 10000);
      logger.info(`Retrying in ${delay}ms...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

export async function disconnectDatabase(): Promise<void> {
  await mongoose.disconnect();
  logger.info('MongoDB disconnected');
}
