import 'reflect-metadata'; // MUST BE FIRST
import { createExpressServer, useContainer } from 'routing-controllers';
import { Container } from 'typedi';
import cors from 'cors';
import { env } from './config/env';
import { connectDatabase } from './config/database';
import { logger } from './utils/logger';
import path from 'path';

// Set up TypeDI container
useContainer(Container);

async function bootstrap() {
  try {
    // Connect to database
    await connectDatabase();

    // Create Express server with routing-controllers
    const app = createExpressServer({
      controllers: [path.join(__dirname, '/controllers/*.ts')],
      middlewares: [path.join(__dirname, '/middlewares/*.ts')],
      defaultErrorHandler: true
    });

    // Enable CORS
    app.use(cors());

    // Start server
    app.listen(env.PORT, () => {
      logger.info(`Server started on port ${env.PORT}`);
      logger.info(`Environment: ${env.NODE_ENV}`);
    });
  } catch (error) {
    logger.fatal({ error }, 'Failed to start server');
    console.error('Error details:', error);
    process.exit(1);
  }
}

bootstrap();
