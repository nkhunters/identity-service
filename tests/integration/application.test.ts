import 'reflect-metadata';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { useExpressServer, useContainer } from 'routing-controllers';
import { Container } from 'typedi';
import { ApplicationController } from '../../src/controllers/ApplicationController';
import { OAuthController } from '../../src/controllers/OAuthController';
import { connectDatabase, disconnectDatabase } from '../../src/config/database';
import { Application } from '../../src/models/Application.model';

describe('Application API', () => {
  let app: any;

  beforeAll(async () => {
    await connectDatabase();
    useContainer(Container);

    const expressApp = express();
    app = useExpressServer(expressApp, {
      controllers: [ApplicationController, OAuthController] as any,
      defaultErrorHandler: true
    });
  });

  afterAll(async () => {
    await Application.deleteMany({});
    await disconnectDatabase();
  });

  describe('POST /applications', () => {
    it('should create application and return clientSecret once', async () => {
      const response = await request(app)
        .post('/applications')
        .send({
          applicationName: 'IntegrationTestApp',
          description: 'Test app',
          clientSecret: 'my-test-secret',
          financialId: 'FIN-INT-001',
          channelId: 'CH-001'
        })
        .expect(200);

      expect(response.body.clientId).toHaveLength(8);
      expect(response.body.clientSecret).toBe('my-test-secret'); // Returned once
      expect(response.body.applicationName).toBe('IntegrationTestApp');
    });

    it('should create application with 3Scale enabled', async () => {
      const response = await request(app)
        .post('/applications')
        .send({
          applicationName: 'App3Scale',
          description: 'App with 3Scale',
          clientSecret: 'secret',
          financialId: 'FIN-INT-002',
          channelId: 'CH-001',
          isDeveloperPortalAPIsEnabled: true,
          threeScaleClientId: '3scale-id',
          threeScaleClientSecret: '3scale-secret'
        })
        .expect(200);

      expect(response.body.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(response.body.threeScaleClientId).toBe('3scale-id');
      expect(response.body.threeScaleClientSecret).toBeUndefined(); // Never returned
    });

    it('should fail validation when 3Scale enabled without credentials', async () => {
      const response = await request(app)
        .post('/applications')
        .send({
          applicationName: 'FailApp',
          description: 'Should fail',
          clientSecret: 'secret',
          financialId: 'FIN-INT-003',
          channelId: 'CH-001',
          isDeveloperPortalAPIsEnabled: true
          // Missing threeScaleClientId and threeScaleClientSecret
        })
        .expect(400);

      expect(response.body.errors).toBeDefined();
    });
  });

  describe('GET /applications/me', () => {
    it('should return application details without clientSecret', async () => {
      // Create application first
      const createResponse = await request(app).post('/applications').send({
        applicationName: 'GetTestApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-GET-001',
        channelId: 'CH-001'
      });

      const clientId = createResponse.body.clientId;

      // Get token for authentication
      const tokenResponse = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: 'secret'
      });

      const token = tokenResponse.body.access_token;

      // Get application using token
      const getResponse = await request(app)
        .get('/applications/me')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(getResponse.body.clientId).toBe(clientId);
      expect(getResponse.body.applicationName).toBe('GetTestApp');
      expect(getResponse.body.clientSecret).toBeUndefined(); // Never returned
    });

    it('should reject without authentication', async () => {
      await request(app).get('/applications/me').expect(401);
    });
  });

  describe('GET /applications/me/3scale-credentials', () => {
    let app3ScaleEnabled: any;
    let app3ScaleDisabled: any;
    let tokenEnabled: string;
    let tokenDisabled: string;

    beforeAll(async () => {
      // Create app with 3Scale enabled
      const enabledResp = await request(app).post('/applications').send({
        applicationName: '3ScaleEnabledIntegration',
        description: 'Test with 3Scale',
        clientSecret: 'secret-enabled',
        financialId: 'FIN-3SCALE-INT-001',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: true,
        threeScaleClientId: '3scale-integration-id',
        threeScaleClientSecret: '3scale-integration-secret'
      });

      app3ScaleEnabled = enabledResp.body;

      // Get token for enabled app
      const tokenEnabledResp = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: app3ScaleEnabled.clientId,
        client_secret: 'secret-enabled'
      });

      tokenEnabled = tokenEnabledResp.body.access_token;

      // Create app with 3Scale disabled
      const disabledResp = await request(app).post('/applications').send({
        applicationName: '3ScaleDisabledIntegration',
        description: 'Test without 3Scale',
        clientSecret: 'secret-disabled',
        financialId: 'FIN-3SCALE-INT-002',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: false
      });

      app3ScaleDisabled = disabledResp.body;

      // Get token for disabled app
      const tokenDisabledResp = await request(app).post('/oauth/token').send({
        grant_type: 'client_credentials',
        client_id: app3ScaleDisabled.clientId,
        client_secret: 'secret-disabled'
      });

      tokenDisabled = tokenDisabledResp.body.access_token;
    });

    it('should return decrypted 3Scale credentials when enabled', async () => {
      const response = await request(app)
        .get('/applications/me/3scale-credentials')
        .set('Authorization', `Bearer ${tokenEnabled}`)
        .expect(200);

      expect(response.body.threeScaleClientId).toBe('3scale-integration-id');
      expect(response.body.threeScaleClientSecret).toBe(
        '3scale-integration-secret'
      );
      expect(response.body.message).toBeDefined();
    });

    it('should reject when 3Scale not enabled', async () => {
      await request(app)
        .get('/applications/me/3scale-credentials')
        .set('Authorization', `Bearer ${tokenDisabled}`)
        .expect(500); // ForbiddenError returns 500 with default error handler
    });

    it('should reject without authentication', async () => {
      await request(app)
        .get('/applications/me/3scale-credentials')
        .expect(401);
    });
  });
});
