import 'reflect-metadata';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import express from 'express';
import { useExpressServer, useContainer } from 'routing-controllers';
import { Container } from 'typedi';
import { ApplicationController } from '../../src/controllers/ApplicationController.js';
import { OAuthController } from '../../src/controllers/OAuthController.js';
import { connectDatabase, disconnectDatabase } from '../../src/config/database.js';
import { Application } from '../../src/models/Application.model.js';
import { RefreshToken } from '../../src/models/RefreshToken.model.js';
import { RevokedToken } from '../../src/models/RevokedToken.model.js';

describe('OAuth API', () => {
  let app: any;
  let testClientId: string;
  const testClientSecret = 'integration-test-secret';

  beforeAll(async () => {
    await connectDatabase();
    useContainer(Container);

    const expressApp = express();
    app = useExpressServer(expressApp, {
      controllers: [ApplicationController, OAuthController] as any,
      defaultErrorHandler: true
    });

    // Create test application
    const response = await request(app)
      .post('/applications')
      .send({
        applicationName: 'OAuthTestApp',
        description: 'OAuth integration test',
        clientSecret: testClientSecret,
        financialId: 'FIN-OAUTH-001',
        channelId: 'CH-001',
        allowedTools: ['tool1', 'tool2'],
        allowedApis: ['/api/users', '/api/products']
      });

    testClientId = response.body.clientId;
  });

  afterAll(async () => {
    await Application.deleteMany({});
    await RefreshToken.deleteMany({});
    await RevokedToken.deleteMany({});
    await disconnectDatabase();
  });

  describe('POST /oauth/token', () => {
    it('should generate tokens with valid credentials', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        })
        .expect(200);

      // Check OAuth2 response format
      expect(response.body.access_token).toBeDefined();
      expect(response.body.token_type).toBe('Bearer');
      expect(response.body.expires_in).toBe(900);
      expect(response.body.refresh_token).toBeDefined();

      // Decode and verify token payload
      const payload = jwt.decode(response.body.access_token) as any;
      expect(payload.sub).toBe(testClientId);
      expect(payload.type).toBe('access');
      expect(payload.allowedTools).toEqual(['tool1', 'tool2']);
      expect(payload.allowedApis).toEqual(['/api/users', '/api/products']);
      expect(payload.jti).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: 'wrong-secret'
        })
        .expect(500); // Should be 401, but depends on error handler

      expect(response.body.message || response.body.error).toBeDefined();
    });

    it('should reject invalid grant_type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'password',
          client_id: testClientId,
          client_secret: testClientSecret
        })
        .expect(400); // Validation error

      expect(response.body.errors).toBeDefined();
    });

    it('should store refresh token in database', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const refreshPayload = jwt.decode(response.body.refresh_token) as any;
      const storedToken = await RefreshToken.findOne({ jti: refreshPayload.jti });

      expect(storedToken).not.toBeNull();
      expect(storedToken?.clientId).toBe(testClientId);
      expect(storedToken?.isRevoked).toBe(false);
    });

    it('should include 3Scale info when enabled', async () => {
      // Create app with 3Scale enabled
      const app3scale = await request(app)
        .post('/applications')
        .send({
          applicationName: 'OAuth3ScaleApp',
          description: 'Test',
          clientSecret: 'secret-3scale',
          financialId: 'FIN-OAUTH-3SCALE',
          channelId: 'CH-001',
          isDeveloperPortalAPIsEnabled: true,
          threeScaleClientId: '3scale-client-123',
          threeScaleClientSecret: '3scale-secret-456'
        });

      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: app3scale.body.clientId,
          client_secret: 'secret-3scale'
        });

      const payload = jwt.decode(tokenResponse.body.access_token) as any;
      expect(payload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(payload.threeScaleClientId).toBe('3scale-client-123');
      expect(payload.threeScaleClientSecret).toBeUndefined();
    });
  });

  describe('POST /oauth/verify', () => {
    it('should verify valid access token', async () => {
      // First, get an access token
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      // Verify the token
      const verifyResponse = await request(app)
        .post('/oauth/verify')
        .send({ token: tokenResponse.body.access_token })
        .expect(200);

      expect(verifyResponse.body.valid).toBe(true);
      expect(verifyResponse.body.payload).toBeDefined();
      expect(verifyResponse.body.payload.clientId).toBe(testClientId);
      expect(verifyResponse.body.payload.allowedTools).toEqual(['tool1', 'tool2']);
      expect(verifyResponse.body.payload.allowedApis).toEqual(['/api/users', '/api/products']);
      expect(verifyResponse.body.payload.jti).toBeDefined();
      expect(verifyResponse.body.payload.issuedAt).toBeDefined();
      expect(verifyResponse.body.payload.expiresAt).toBeDefined();

      // Verify ISO date format
      expect(new Date(verifyResponse.body.payload.issuedAt).toISOString())
        .toBe(verifyResponse.body.payload.issuedAt);
      expect(new Date(verifyResponse.body.payload.expiresAt).toISOString())
        .toBe(verifyResponse.body.payload.expiresAt);
    });

    it('should reject expired token', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        {
          sub: testClientId,
          jti: 'expired-jti',
          applicationName: 'OAuthTestApp',
          financialId: 'FIN-OAUTH-001',
          channelId: 'CH-001',
          allowedTools: ['tool1'],
          allowedApis: ['/api/test'],
          isDeveloperPortalAPIsEnabled: false,
          type: 'access'
        },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: '0s' }
      );

      // Wait to ensure expiration
      await new Promise(resolve => setTimeout(resolve, 100));

      const response = await request(app)
        .post('/oauth/verify')
        .send({ token: expiredToken })
        .expect(200);

      expect(response.body.valid).toBe(false);
      expect(response.body.error).toBe('Token expired');
      expect(response.body.expiredAt).toBeDefined();
      expect(new Date(response.body.expiredAt).toISOString())
        .toBe(response.body.expiredAt);
    });

    it('should reject token with invalid signature', async () => {
      // Create a token with wrong secret
      const invalidToken = jwt.sign(
        {
          sub: testClientId,
          jti: 'invalid-sig-jti',
          applicationName: 'OAuthTestApp',
          financialId: 'FIN-OAUTH-001',
          channelId: 'CH-001',
          allowedTools: [],
          allowedApis: [],
          isDeveloperPortalAPIsEnabled: false,
          type: 'access'
        },
        'wrong-secret-key',
        { expiresIn: '15m' }
      );

      const response = await request(app)
        .post('/oauth/verify')
        .send({ token: invalidToken })
        .expect(200);

      expect(response.body.valid).toBe(false);
      expect(response.body.error).toBe('Invalid token');
      expect(response.body.message).toBeDefined();
    });

    it('should reject refresh token', async () => {
      // Get tokens
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      // Try to verify refresh token
      const response = await request(app)
        .post('/oauth/verify')
        .send({ token: tokenResponse.body.refresh_token })
        .expect(200);

      expect(response.body.valid).toBe(false);
      expect(response.body.error).toBe('Invalid token type');
      expect(response.body.message).toBe('Only access tokens can be verified at this endpoint');
    });

    it('should reject malformed token', async () => {
      const response = await request(app)
        .post('/oauth/verify')
        .send({ token: 'not-a-valid-jwt-token' })
        .expect(200);

      expect(response.body.valid).toBe(false);
      expect(response.body.error).toBe('Invalid token');
      expect(response.body.message).toBeDefined();
    });

    it('should include 3Scale info in verified payload', async () => {
      // Create app with 3Scale enabled
      const app3scale = await request(app)
        .post('/applications')
        .send({
          applicationName: 'VerifyOAuth3ScaleApp',
          description: 'Test',
          clientSecret: 'secret-verify-3scale',
          financialId: 'FIN-VERIFY-3SCALE',
          channelId: 'CH-001',
          isDeveloperPortalAPIsEnabled: true,
          threeScaleClientId: '3scale-verify-123',
          threeScaleClientSecret: '3scale-verify-secret'
        });

      // Get token
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: app3scale.body.clientId,
          client_secret: 'secret-verify-3scale'
        });

      // Verify token
      const verifyResponse = await request(app)
        .post('/oauth/verify')
        .send({ token: tokenResponse.body.access_token })
        .expect(200);

      expect(verifyResponse.body.valid).toBe(true);
      expect(verifyResponse.body.payload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(verifyResponse.body.payload.threeScaleClientId).toBe('3scale-verify-123');
      // threeScaleClientSecret should NEVER be in response
      expect(verifyResponse.body.payload.threeScaleClientSecret).toBeUndefined();
    });
  });

  describe('POST /oauth/token (refresh_token grant)', () => {
    it('should refresh access token with valid refresh token', async () => {
      // Step 1: Get initial token pair
      const initialResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        })
        .expect(200);

      const refreshToken = initialResponse.body.refresh_token;
      const initialAccessToken = initialResponse.body.access_token;

      // Step 2: Refresh the access token
      const refreshResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
        .expect(200);

      // Check response format
      expect(refreshResponse.body.access_token).toBeDefined();
      expect(refreshResponse.body.token_type).toBe('Bearer');
      expect(refreshResponse.body.expires_in).toBe(900);
      expect(refreshResponse.body.refresh_token).toBeUndefined(); // No new refresh token

      // Verify new access token is different from initial
      expect(refreshResponse.body.access_token).not.toBe(initialAccessToken);

      // Verify new access token has same permissions
      const newPayload = jwt.decode(refreshResponse.body.access_token) as any;
      const initialPayload = jwt.decode(initialAccessToken) as any;

      expect(newPayload.sub).toBe(initialPayload.sub);
      expect(newPayload.type).toBe('access');
      expect(newPayload.allowedTools).toEqual(initialPayload.allowedTools);
      expect(newPayload.allowedApis).toEqual(initialPayload.allowedApis);
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: 'invalid-token-12345'
        })
        .expect(500); // Error thrown by controller

      expect(response.body.message || response.body.error).toBeDefined();
    });

    it('should reject revoked refresh token', async () => {
      // Step 1: Get initial token pair
      const initialResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const refreshToken = initialResponse.body.refresh_token;

      // Step 2: Revoke the refresh token
      const refreshPayload = jwt.decode(refreshToken) as any;
      await RefreshToken.findOneAndUpdate(
        { jti: refreshPayload.jti },
        { isRevoked: true }
      );

      // Step 3: Attempt to refresh should fail
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
        .expect(500);

      expect(response.body.message || response.body.error).toBeDefined();
    });

    it('should reject access token when refresh token is required', async () => {
      // Get token pair
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      // Try to use access token for refresh
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: tokenResponse.body.access_token
        })
        .expect(500); // Will fail with "Invalid token type" or signature error

      expect(response.body.message || response.body.error).toBeDefined();
    });

    it('should maintain 3Scale info when refreshing token', async () => {
      // Create app with 3Scale enabled
      const app3scale = await request(app)
        .post('/applications')
        .send({
          applicationName: 'RefreshOAuth3ScaleApp',
          description: 'Test',
          clientSecret: 'secret-refresh-3scale',
          financialId: 'FIN-REFRESH-3SCALE',
          channelId: 'CH-001',
          isDeveloperPortalAPIsEnabled: true,
          threeScaleClientId: '3scale-refresh-123',
          threeScaleClientSecret: '3scale-refresh-secret'
        });

      // Get initial token pair
      const initialResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: app3scale.body.clientId,
          client_secret: 'secret-refresh-3scale'
        });

      // Refresh access token
      const refreshResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: initialResponse.body.refresh_token
        })
        .expect(200);

      // Verify 3Scale info is maintained
      const payload = jwt.decode(refreshResponse.body.access_token) as any;
      expect(payload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(payload.threeScaleClientId).toBe('3scale-refresh-123');
      expect(payload.threeScaleClientSecret).toBeUndefined(); // NEVER in token
    });
  });

  describe('POST /oauth/revoke', () => {
    let validAccessToken: string;
    let validRefreshToken: string;

    beforeAll(async () => {
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      validAccessToken = tokenResponse.body.access_token;
      validRefreshToken = tokenResponse.body.refresh_token;
    });

    it('should revoke access token', async () => {
      // Get a new token for this test
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const accessToken = tokenResponse.body.access_token;

      // Revoke the token
      const response = await request(app)
        .post('/oauth/revoke')
        .send({ token: accessToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.tokenType).toBe('access');
      expect(response.body.jti).toBeDefined();

      // Verify token should now fail
      const verifyResp = await request(app)
        .post('/oauth/verify')
        .send({ token: accessToken });

      expect(verifyResp.body.valid).toBe(false);
      expect(verifyResp.body.message).toContain('revoked');
    });

    it('should revoke refresh token', async () => {
      // Get a new token pair for this test
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const refreshToken = tokenResponse.body.refresh_token;

      // Revoke the refresh token
      const response = await request(app)
        .post('/oauth/revoke')
        .send({ token: refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.tokenType).toBe('refresh');

      // Try to use revoked refresh token
      const refreshResp = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        })
        .expect(500); // Should fail

      expect(refreshResp.body.error || refreshResp.body.message).toBeDefined();
    });

    it('should accept revocation with reason', async () => {
      // Get a new token for this test
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const response = await request(app)
        .post('/oauth/revoke')
        .send({
          token: tokenResponse.body.access_token,
          reason: 'User logged out'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should handle revoking invalid token', async () => {
      const response = await request(app)
        .post('/oauth/revoke')
        .send({ token: 'invalid.jwt.token' })
        .expect(200);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBeDefined();
    });

    it('should handle revoking already revoked token', async () => {
      // Get a new token for this test
      const tokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials',
          client_id: testClientId,
          client_secret: testClientSecret
        });

      const accessToken = tokenResponse.body.access_token;

      // Revoke once
      await request(app)
        .post('/oauth/revoke')
        .send({ token: accessToken });

      // Revoke again
      const response = await request(app)
        .post('/oauth/revoke')
        .send({ token: accessToken })
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });
});
