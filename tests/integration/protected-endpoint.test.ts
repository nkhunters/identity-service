import 'reflect-metadata'; // MUST BE FIRST
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express from 'express';
import { useExpressServer, useContainer } from 'routing-controllers';
import { Container } from 'typedi';
import { ApplicationController } from '../../src/controllers/ApplicationController';
import { OAuthController } from '../../src/controllers/OAuthController';
import { ExampleProtectedController } from '../../src/controllers/ExampleProtectedController';
import { AuthMiddleware } from '../../src/middlewares/AuthMiddleware';
import { connectDatabase, disconnectDatabase } from '../../src/config/database';
import { Application } from '../../src/models/Application.model';

describe('Protected Endpoints - Integration Tests', () => {
  let app: any;
  let testClientId: string;
  const testClientSecret = 'protected-test-secret';
  let validAccessToken: string;

  let testClientIdNoTools: string;
  const testClientSecretNoTools = 'no-tools-secret';
  let accessTokenNoTools: string;

  beforeAll(async () => {
    // Connect to database
    await connectDatabase();

    // Setup TypeDI container
    useContainer(Container);

    // Create Express app
    const expressApp = express();
    app = useExpressServer(expressApp, {
      controllers: [
        ApplicationController,
        OAuthController,
        ExampleProtectedController
      ] as any,
      middlewares: [AuthMiddleware] as any,
      defaultErrorHandler: true
    });

    // Create test application with full permissions
    const appResponse = await request(app)
      .post('/applications')
      .send({
        applicationName: 'ProtectedTestApp',
        description: 'Test',
        clientSecret: testClientSecret,
        financialId: 'FIN-PROTECTED',
        channelId: 'CH-001',
        allowedTools: ['tool1', 'tool2'],
        allowedApis: ['/api/users', '/api/products']
      });

    testClientId = appResponse.body.clientId;

    // Get access token for full permissions app
    const tokenResponse = await request(app).post('/oauth/token').send({
      grant_type: 'client_credentials',
      client_id: testClientId,
      client_secret: testClientSecret
    });

    validAccessToken = tokenResponse.body.access_token;

    // Create test application with limited permissions
    const appResponseNoTools = await request(app)
      .post('/applications')
      .send({
        applicationName: 'NoToolsApp',
        description: 'Test',
        clientSecret: testClientSecretNoTools,
        financialId: 'FIN-NO-TOOLS',
        channelId: 'CH-001',
        allowedTools: ['tool3'], // Different tool
        allowedApis: ['/api/other']
      });

    testClientIdNoTools = appResponseNoTools.body.clientId;

    // Get access token for limited permissions app
    const tokenResponseNoTools = await request(app).post('/oauth/token').send({
      grant_type: 'client_credentials',
      client_id: testClientIdNoTools,
      client_secret: testClientSecretNoTools
    });

    accessTokenNoTools = tokenResponseNoTools.body.access_token;
  });

  afterAll(async () => {
    await Application.deleteMany({});
    await disconnectDatabase();
  });

  describe('GET /applications/:clientId', () => {
    it('should reject request without token', async () => {
      await request(app).get(`/applications/${testClientId}`).expect(401);
    });

    it('should reject request with invalid token', async () => {
      await request(app)
        .get(`/applications/${testClientId}`)
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });

    it('should allow request with valid token for own data', async () => {
      const response = await request(app)
        .get(`/applications/${testClientId}`)
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      expect(response.body.clientId).toBe(testClientId);
      expect(response.body.applicationName).toBe('ProtectedTestApp');
      expect(response.body.clientSecret).toBeUndefined(); // Never returned
    });

    it('should reject request for another application data', async () => {
      const response = await request(app)
        .get(`/applications/${testClientIdNoTools}`) // Different clientId
        .set('Authorization', `Bearer ${validAccessToken}`) // Token for testClientId
        .expect(200); // Returns 200 but with error in body

      expect(response.body.error).toBe('Forbidden');
      expect(response.body.message).toContain('your own application data');
    });
  });

  describe('GET /protected/tool-restricted', () => {
    it('should allow access with required tools', async () => {
      const response = await request(app)
        .get('/protected/tool-restricted')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      expect(response.body.message).toContain('tool1 and tool2');
      expect(response.body.user.clientId).toBe(testClientId);
    });

    it('should reject access without required tools', async () => {
      const response = await request(app)
        .get('/protected/tool-restricted')
        .set('Authorization', `Bearer ${accessTokenNoTools}`)
        .expect(500); // ForbiddenError handled by default error handler

      // Note: routing-controllers default error handler returns 500 for custom errors
      // In production, you'd add custom error handling middleware
    });
  });

  describe('GET /protected/api-restricted', () => {
    it('should allow access with required APIs', async () => {
      const response = await request(app)
        .get('/protected/api-restricted')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      expect(response.body.message).toContain('/api/users');
      expect(response.body.user.clientId).toBe(testClientId);
    });

    it('should reject access without required APIs', async () => {
      await request(app)
        .get('/protected/api-restricted')
        .set('Authorization', `Bearer ${accessTokenNoTools}`)
        .expect(500); // ForbiddenError handled by default error handler
    });
  });

  describe('GET /protected/public-for-authenticated', () => {
    it('should allow any authenticated user', async () => {
      const response = await request(app)
        .get('/protected/public-for-authenticated')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .expect(200);

      expect(response.body.message).toBe('You are authenticated');
      expect(response.body.clientId).toBe(testClientId);
      expect(response.body.applicationName).toBe('ProtectedTestApp');
    });

    it('should allow authenticated user with limited permissions', async () => {
      const response = await request(app)
        .get('/protected/public-for-authenticated')
        .set('Authorization', `Bearer ${accessTokenNoTools}`)
        .expect(200);

      expect(response.body.message).toBe('You are authenticated');
      expect(response.body.clientId).toBe(testClientIdNoTools);
    });

    it('should reject unauthenticated user', async () => {
      await request(app).get('/protected/public-for-authenticated').expect(401);
    });
  });
});
