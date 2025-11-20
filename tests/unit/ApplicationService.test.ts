import 'reflect-metadata';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Container } from 'typedi';
import { ApplicationService } from '../../src/services/ApplicationService';
import { EncryptionService } from '../../src/services/EncryptionService';
import { Application } from '../../src/models/Application.model';
import { connectDatabase, disconnectDatabase } from '../../src/config/database';

describe('ApplicationService', () => {
  let applicationService: ApplicationService;

  beforeEach(async () => {
    await connectDatabase();
    // Reset container and register services
    Container.reset();
    const encryptionService = new EncryptionService();
    Container.set(EncryptionService, encryptionService);
    applicationService = new ApplicationService(encryptionService);
  });

  afterEach(async () => {
    await Application.deleteMany({});
    await disconnectDatabase();
  });

  describe('createApplication', () => {
    it('should generate unique 8-character clientId', async () => {
      const dto = {
        applicationName: 'TestApp',
        description: 'Test application',
        clientSecret: 'test-secret-123',
        financialId: 'FIN-001',
        channelId: 'CH-001'
      };

      const app = await applicationService.createApplication(dto);

      expect(app.clientId).toHaveLength(8);
      expect(app.clientId).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should hash clientSecret before storing', async () => {
      const dto = {
        applicationName: 'TestApp2',
        description: 'Test',
        clientSecret: 'my-secret',
        financialId: 'FIN-002',
        channelId: 'CH-001'
      };

      const app = await applicationService.createApplication(dto);

      expect(app.clientSecret).not.toBe(dto.clientSecret);
      expect(app.clientSecret).toContain(':'); // salt:hash format
    });

    it('should encrypt 3Scale clientSecret when enabled', async () => {
      const dto = {
        applicationName: 'TestApp3',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-003',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: true,
        threeScaleClientId: '3scale-id',
        threeScaleClientSecret: '3scale-secret'
      };

      const app = await applicationService.createApplication(dto);

      expect(app.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(app.threeScaleClientId).toBe('3scale-id');
      expect(app.threeScaleClientSecret).not.toBe('3scale-secret');
      expect(app.threeScaleClientSecret).toContain(':'); // iv:authTag:encrypted
    });
  });

  describe('validateCredentials', () => {
    it('should return application for valid credentials', async () => {
      const dto = {
        applicationName: 'TestApp4',
        description: 'Test',
        clientSecret: 'correct-password',
        financialId: 'FIN-004',
        channelId: 'CH-001'
      };

      const created = await applicationService.createApplication(dto);
      const validated = await applicationService.validateCredentials(
        created.clientId,
        'correct-password'
      );

      expect(validated).not.toBeNull();
      expect(validated?.clientId).toBe(created.clientId);
    });

    it('should return null for invalid credentials', async () => {
      const dto = {
        applicationName: 'TestApp5',
        description: 'Test',
        clientSecret: 'correct-password',
        financialId: 'FIN-005',
        channelId: 'CH-001'
      };

      const created = await applicationService.createApplication(dto);
      const validated = await applicationService.validateCredentials(
        created.clientId,
        'wrong-password'
      );

      expect(validated).toBeNull();
    });
  });
});
