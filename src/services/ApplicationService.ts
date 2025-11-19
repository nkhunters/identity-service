import { Service, Inject } from 'typedi';
import { nanoid } from 'nanoid';
import { Application, ApplicationDocument } from '../models/Application.model.js';
import { EncryptionService } from './EncryptionService.js';
import { CreateApplicationDto } from '../dto/CreateApplicationDto.js';
import { logger } from '../utils/logger.js';

@Service()
export class ApplicationService {
  constructor(
    @Inject() private encryptionService: EncryptionService
  ) {}

  async createApplication(dto: CreateApplicationDto): Promise<ApplicationDocument> {
    // Generate unique 8-character clientId
    const clientId = nanoid(8);

    // Hash clientSecret
    const hashedSecret = await this.encryptionService.hash(dto.clientSecret);

    // Encrypt 3Scale clientSecret if provided
    let encryptedThreeScaleSecret: string | undefined;
    if (dto.isDeveloperPortalAPIsEnabled && dto.threeScaleClientSecret) {
      encryptedThreeScaleSecret = this.encryptionService.encrypt(dto.threeScaleClientSecret);
    }

    // Create application
    const application = await Application.create({
      applicationName: dto.applicationName,
      description: dto.description,
      clientId,
      clientSecret: hashedSecret,
      financialId: dto.financialId,
      channelId: dto.channelId,
      allowedTools: dto.allowedTools || [],
      allowedApis: dto.allowedApis || [],
      isDeveloperPortalAPIsEnabled: dto.isDeveloperPortalAPIsEnabled || false,
      threeScaleClientId: dto.threeScaleClientId,
      threeScaleClientSecret: encryptedThreeScaleSecret,
      isActive: true
    });

    logger.info({ clientId, applicationName: dto.applicationName }, 'Application created');

    return application;
  }

  async findByClientId(clientId: string): Promise<ApplicationDocument | null> {
    return Application.findOne({ clientId, isActive: true });
  }

  async validateCredentials(clientId: string, clientSecret: string): Promise<ApplicationDocument | null> {
    const application = await this.findByClientId(clientId);

    if (!application) {
      return null;
    }

    // Verify clientSecret using timing-safe comparison
    const isValid = await this.encryptionService.verify(clientSecret, application.clientSecret);

    return isValid ? application : null;
  }
}
