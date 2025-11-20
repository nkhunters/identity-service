import {
  JsonController,
  Post,
  Body,
  Get,
  UseBefore,
  Req
} from 'routing-controllers';
import { Service, Container } from 'typedi';
import { ApplicationService } from '../services/ApplicationService';
import { EncryptionService } from '../services/EncryptionService';
import { CreateApplicationDto } from '../dto/CreateApplicationDto';
import { AuthMiddleware } from '../middlewares/AuthMiddleware';
import { AuthenticatedRequest } from '../types/AuthenticatedRequest';
import { ForbiddenError, NotFoundError } from '../utils/errors';
import { logger } from '../utils/logger';

@Service()
@JsonController('/applications')
export class ApplicationController {
  constructor(private applicationService: ApplicationService) {}

  @Post()
  async create(@Body() dto: CreateApplicationDto) {
    const application = await this.applicationService.createApplication(dto);

    // CRITICAL: Return plaintext clientSecret ONLY on creation
    return {
      clientId: application.clientId,
      clientSecret: dto.clientSecret, // Plaintext, returned ONCE
      applicationName: application.applicationName,
      description: application.description,
      financialId: application.financialId,
      channelId: application.channelId,
      allowedTools: application.allowedTools,
      allowedApis: application.allowedApis,
      isDeveloperPortalAPIsEnabled: application.isDeveloperPortalAPIsEnabled,
      threeScaleClientId: application.threeScaleClientId,
      // NOTE: Never return threeScaleClientSecret (even encrypted)
      isActive: application.isActive,
      createdAt: application.createdAt
    };
  }

  @Get()
  @UseBefore(AuthMiddleware) // Protect this endpoint
  async getMyApplication(@Req() request: AuthenticatedRequest) {
    // Extract clientId from token
    const clientId = request.user!.sub;

    const application = await this.applicationService.findByClientId(clientId);

    if (!application) {
      throw new NotFoundError('Application not found');
    }

    // Return application details WITHOUT clientSecret
    return {
      clientId: application.clientId,
      applicationName: application.applicationName,
      description: application.description,
      financialId: application.financialId,
      channelId: application.channelId,
      allowedTools: application.allowedTools,
      allowedApis: application.allowedApis,
      isDeveloperPortalAPIsEnabled: application.isDeveloperPortalAPIsEnabled,
      threeScaleClientId: application.threeScaleClientId,
      isActive: application.isActive,
      createdAt: application.createdAt
    };
  }

  @Get('/3scale-credentials')
  @UseBefore(AuthMiddleware)
  async getMy3ScaleCredentials(@Req() request: AuthenticatedRequest) {
    // Extract clientId from token
    const clientId = request.user!.sub;

    logger.info({ clientId }, 'Fetching 3Scale credentials from token');

    // Fetch application from database
    const application = await this.applicationService.findByClientId(clientId);

    if (!application) {
      logger.warn(
        { clientId },
        '3Scale credentials requested for non-existent application'
      );
      throw new NotFoundError('Application not found');
    }

    // Check if Developer Portal APIs are enabled
    if (!application.isDeveloperPortalAPIsEnabled) {
      logger.info(
        { clientId },
        '3Scale credentials requested but Developer Portal APIs not enabled'
      );
      throw new ForbiddenError(
        'Developer Portal APIs are not enabled for this application'
      );
    }

    // Check if 3Scale credentials exist
    if (
      !application.threeScaleClientId ||
      !application.threeScaleClientSecret
    ) {
      logger.warn({ clientId }, '3Scale enabled but credentials missing');
      throw new NotFoundError(
        '3Scale credentials not found. Please contact support.'
      );
    }

    // Decrypt 3Scale clientSecret
    let decryptedSecret: string;
    try {
      const encryptionService = Container.get(EncryptionService);
      decryptedSecret = encryptionService.decrypt(
        application.threeScaleClientSecret
      );
    } catch (error) {
      logger.error(
        {
          clientId,
          error
        },
        'Failed to decrypt 3Scale clientSecret'
      );
      throw new Error(
        'Failed to retrieve 3Scale credentials. Please contact support.'
      );
    }

    // Log credential access for audit
    logger.info(
      {
        clientId,
        threeScaleClientId: application.threeScaleClientId
      },
      '3Scale credentials accessed'
    );

    // Return decrypted credentials
    return {
      threeScaleClientId: application.threeScaleClientId,
      threeScaleClientSecret: decryptedSecret,
      message: 'Use these credentials to access 3Scale Developer Portal APIs'
    };
  }
}
