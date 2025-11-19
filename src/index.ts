import 'reflect-metadata'; // MUST BE FIRST
import { createExpressServer, useContainer } from 'routing-controllers';
import { Container } from 'typedi';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path, { dirname } from 'path';
import { env } from './config/env.js';
import { connectDatabase } from './config/database.js';
import { logger } from './utils/logger.js';
import { ApplicationController } from './controllers/ApplicationController.js';
import { OAuthController } from './controllers/OAuthController.js';
import { ExampleProtectedController } from './controllers/ExampleProtectedController.js';
import { AuthMiddleware } from './middlewares/AuthMiddleware.js';
import { HealthController } from './controllers/HealthController.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
console.log(__dirname);
// Set up TypeDI container
useContainer(Container);

async function bootstrap() {
  try {
    // Connect to database
    await connectDatabase();

    // Create Express server with routing-controllers
    const app = createExpressServer({
      controllers: [
        HealthController,
        ApplicationController,
        OAuthController
      ] as any,
      middlewares: ['src/middlewares'],
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
