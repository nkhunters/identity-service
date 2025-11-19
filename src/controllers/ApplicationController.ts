import { JsonController, Post, Body, Get, Param, UseBefore, Req } from 'routing-controllers';
import { Inject, Service, Container } from 'typedi';
import { ApplicationService } from '../services/ApplicationService.js';
import { EncryptionService } from '../services/EncryptionService.js';
import { CreateApplicationDto } from '../dto/CreateApplicationDto.js';
import { AuthMiddleware } from '../middlewares/AuthMiddleware.js';
import { AuthenticatedRequest } from '../types/AuthenticatedRequest.js';
import { ForbiddenError, NotFoundError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';

@Service()
@JsonController('/applications')
export class ApplicationController {
  constructor(
    @Inject() private applicationService: ApplicationService
  ) {}

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

  @Get('/:clientId')
  @UseBefore(AuthMiddleware) // Protect this endpoint
  async getByClientId(
    @Param('clientId') clientId: string,
    @Req() request: AuthenticatedRequest
  ) {
    const application = await this.applicationService.findByClientId(clientId);

    if (!application) {
      return { error: 'Application not found' };
    }

    // Authorization check: User can only access their own application data
    if (request.user!.sub !== clientId) {
      return {
        error: 'Forbidden',
        message: 'You can only access your own application data'
      };
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

  @Get('/:clientId/3scale-credentials')
  @UseBefore(AuthMiddleware)
  async get3ScaleCredentials(
    @Param('clientId') clientId: string,
    @Req() request: AuthenticatedRequest
  ) {
    // Verify requesting application
    if (!request.user) {
      logger.warn({ clientId }, '3Scale credentials access without authentication');
      throw new ForbiddenError('Authentication required');
    }

    // Security: Applications can only access their own 3Scale credentials
    if (request.user.sub !== clientId) {
      logger.warn(
        {
          requestingClientId: request.user.sub,
          targetClientId: clientId
        },
        'Attempted unauthorized 3Scale credentials access'
      );
      throw new ForbiddenError('You can only access your own 3Scale credentials');
    }

    // Fetch application from database
    const application = await this.applicationService.findByClientId(clientId);

    if (!application) {
      logger.warn({ clientId }, '3Scale credentials requested for non-existent application');
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
    if (!application.threeScaleClientId || !application.threeScaleClientSecret) {
      logger.warn(
        { clientId },
        '3Scale enabled but credentials missing'
      );
      throw new NotFoundError(
        '3Scale credentials not found. Please contact support.'
      );
    }

    // Decrypt 3Scale clientSecret
    let decryptedSecret: string;
    try {
      const encryptionService = Container.get(EncryptionService);
      decryptedSecret = encryptionService.decrypt(application.threeScaleClientSecret);
    } catch (error) {
      logger.error(
        {
          clientId,
          error
        },
        'Failed to decrypt 3Scale clientSecret'
      );
      throw new Error('Failed to retrieve 3Scale credentials. Please contact support.');
    }

    // Log credential access for audit
    logger.info(
      {
        clientId,
        requestingClientId: request.user.sub,
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
