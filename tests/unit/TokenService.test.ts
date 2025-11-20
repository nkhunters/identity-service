import 'reflect-metadata';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Container } from 'typedi';
import jwt from 'jsonwebtoken';
import { TokenService } from '../../src/services/TokenService';
import { ApplicationService } from '../../src/services/ApplicationService';
import { EncryptionService } from '../../src/services/EncryptionService';
import { RefreshToken } from '../../src/models/RefreshToken.model';
import { RevokedToken } from '../../src/models/RevokedToken.model';
import { Application } from '../../src/models/Application.model';
import { connectDatabase, disconnectDatabase } from '../../src/config/database';

describe('TokenService', () => {
  let tokenService: TokenService;
  let applicationService: ApplicationService;

  beforeEach(async () => {
    await connectDatabase();
    // Reset container and register services
    Container.reset();
    const encryptionService = new EncryptionService();
    Container.set(EncryptionService, encryptionService);
    tokenService = new TokenService(encryptionService);
    applicationService = new ApplicationService(encryptionService);
  });

  afterEach(async () => {
    await Application.deleteMany({});
    await RefreshToken.deleteMany({});
    await RevokedToken.deleteMany({});
    await disconnectDatabase();
  });

  describe('generateTokenPair', () => {
    it('should generate valid access and refresh tokens', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'TokenTestApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-TOKEN-001',
        channelId: 'CH-001',
        allowedTools: ['tool1'],
        allowedApis: ['/api/test']
      });

      const tokens = await tokenService.generateTokenPair(app);

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();

      // Verify access token structure
      const accessPayload = jwt.decode(tokens.accessToken) as any;
      expect(accessPayload.sub).toBe(app.clientId);
      expect(accessPayload.type).toBe('access');
      expect(accessPayload.allowedTools).toEqual(['tool1']);
      expect(accessPayload.allowedApis).toEqual(['/api/test']);
      expect(accessPayload.isDeveloperPortalAPIsEnabled).toBe(false);
    });

    it('should include 3Scale info when enabled', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'Token3ScaleApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-TOKEN-002',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: true,
        threeScaleClientId: '3scale-id-123',
        threeScaleClientSecret: '3scale-secret-456'
      });

      const tokens = await tokenService.generateTokenPair(app);
      const accessPayload = jwt.decode(tokens.accessToken) as any;

      expect(accessPayload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(accessPayload.threeScaleClientId).toBe('3scale-id-123');
      expect(accessPayload.threeScaleClientSecret).toBeUndefined(); // NEVER in token
    });

    it('should store hashed refresh token in database', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'TokenHashApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-TOKEN-003',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);
      const refreshPayload = jwt.decode(tokens.refreshToken) as any;

      const storedToken = await RefreshToken.findOne({
        jti: refreshPayload.jti
      });

      expect(storedToken).not.toBeNull();
      expect(storedToken?.token).not.toBe(tokens.refreshToken); // Hashed
      expect(storedToken?.token).toContain(':'); // salt:hash format
      expect(storedToken?.clientId).toBe(app.clientId);
    });

    it('should set correct expiration times', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'TokenExpiryApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-TOKEN-004',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);

      const accessPayload = jwt.decode(tokens.accessToken) as any;
      const refreshPayload = jwt.decode(tokens.refreshToken) as any;

      // Access token should expire in ~15 minutes
      const accessExpiry = accessPayload.exp - accessPayload.iat;
      expect(accessExpiry).toBeGreaterThanOrEqual(900); // 15 minutes
      expect(accessExpiry).toBeLessThanOrEqual(901);

      // Refresh token should expire in ~7 days
      const refreshExpiry = refreshPayload.exp - refreshPayload.iat;
      expect(refreshExpiry).toBeGreaterThanOrEqual(604800); // 7 days
      expect(refreshExpiry).toBeLessThanOrEqual(604801);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify valid access token with all fields', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'VerifyApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-VERIFY-001',
        channelId: 'CH-001',
        allowedTools: ['tool1', 'tool2'],
        allowedApis: ['/api/v1', '/api/v2']
      });

      const tokens = await tokenService.generateTokenPair(app);
      const payload = await tokenService.verifyAccessToken(tokens.accessToken);

      expect(payload.sub).toBe(app.clientId);
      expect(payload.type).toBe('access');
      expect(payload.applicationName).toBe('VerifyApp');
      expect(payload.allowedTools).toEqual(['tool1', 'tool2']);
      expect(payload.allowedApis).toEqual(['/api/v1', '/api/v2']);
      expect(payload.jti).toBeDefined();
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
    });

    it('should reject expired access token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'VerifyExpiredApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-VERIFY-002',
        channelId: 'CH-001'
      });

      // Create a token that expires immediately
      const expiredToken = jwt.sign(
        {
          sub: app.clientId,
          jti: 'test-jti-expired',
          applicationName: app.applicationName,
          financialId: app.financialId,
          channelId: app.channelId,
          allowedTools: [],
          allowedApis: [],
          isDeveloperPortalAPIsEnabled: false,
          type: 'access'
        },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: '0s' }
      );

      // Wait a moment to ensure token is expired
      await new Promise((resolve) => setTimeout(resolve, 100));

      await expect(
        tokenService.verifyAccessToken(expiredToken)
      ).rejects.toThrow('jwt expired');
    });

    it('should reject token with invalid signature', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'VerifyInvalidSigApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-VERIFY-003',
        channelId: 'CH-001'
      });

      // Create a token with wrong secret
      const invalidToken = jwt.sign(
        {
          sub: app.clientId,
          jti: 'test-jti-invalid',
          applicationName: app.applicationName,
          financialId: app.financialId,
          channelId: app.channelId,
          allowedTools: [],
          allowedApis: [],
          isDeveloperPortalAPIsEnabled: false,
          type: 'access'
        },
        'wrong-secret',
        { expiresIn: '15m' }
      );

      await expect(
        tokenService.verifyAccessToken(invalidToken)
      ).rejects.toThrow('invalid signature');
    });

    it('should reject refresh token when verifying access', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'VerifyWrongApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-VERIFY-004',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);

      // Refresh tokens are signed with JWT_REFRESH_SECRET, so verifying with
      // JWT_ACCESS_SECRET will fail with "invalid signature" before type check
      await expect(
        tokenService.verifyAccessToken(tokens.refreshToken)
      ).rejects.toThrow('invalid signature');
    });

    it('should verify token with 3Scale info', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'Verify3ScaleApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-VERIFY-005',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: true,
        threeScaleClientId: '3scale-client-123',
        threeScaleClientSecret: '3scale-secret-456'
      });

      const tokens = await tokenService.generateTokenPair(app);
      const payload = await tokenService.verifyAccessToken(tokens.accessToken);

      expect(payload.sub).toBe(app.clientId);
      expect(payload.type).toBe('access');
      expect(payload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(payload.threeScaleClientId).toBe('3scale-client-123');
      // threeScaleClientSecret should NEVER be in the token
      expect((payload as any).threeScaleClientSecret).toBeUndefined();
    });
  });

  describe('refreshAccessToken', () => {
    it('should generate new access token from valid refresh token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RefreshApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REFRESH-001',
        channelId: 'CH-001',
        allowedTools: ['tool1', 'tool2'],
        allowedApis: ['/api/test']
      });

      // Generate initial token pair
      const tokens = await tokenService.generateTokenPair(app);

      // Refresh the access token
      const newAccessToken = await tokenService.refreshAccessToken(
        tokens.refreshToken
      );

      expect(newAccessToken).toBeDefined();
      expect(newAccessToken).not.toBe(tokens.accessToken); // Should be a new token

      // Verify new access token has same permissions
      const newPayload = await tokenService.verifyAccessToken(newAccessToken);
      expect(newPayload.sub).toBe(app.clientId);
      expect(newPayload.type).toBe('access');
      expect(newPayload.applicationName).toBe('RefreshApp');
      expect(newPayload.allowedTools).toEqual(['tool1', 'tool2']);
      expect(newPayload.allowedApis).toEqual(['/api/test']);
    });

    it('should reject revoked refresh token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RefreshRevokedApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REFRESH-002',
        channelId: 'CH-001'
      });

      // Generate token pair
      const tokens = await tokenService.generateTokenPair(app);

      // Revoke the refresh token
      const refreshPayload = jwt.decode(tokens.refreshToken) as any;
      await RefreshToken.findOneAndUpdate(
        { jti: refreshPayload.jti },
        { isRevoked: true }
      );

      // Attempt to refresh should fail
      await expect(
        tokenService.refreshAccessToken(tokens.refreshToken)
      ).rejects.toThrow('Refresh token has been revoked');
    });

    it('should reject expired refresh token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RefreshExpiredApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REFRESH-003',
        channelId: 'CH-001'
      });

      // Create an expired refresh token
      const expiredRefreshToken = jwt.sign(
        {
          sub: app.clientId,
          jti: 'test-jti-refresh-expired',
          applicationName: app.applicationName,
          financialId: app.financialId,
          channelId: app.channelId,
          allowedTools: [],
          allowedApis: [],
          isDeveloperPortalAPIsEnabled: false,
          type: 'refresh'
        },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '0s' }
      );

      // Wait to ensure token is expired
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Attempt to refresh should fail
      await expect(
        tokenService.refreshAccessToken(expiredRefreshToken)
      ).rejects.toThrow('jwt expired');
    });

    it('should reject invalid/tampered refresh token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RefreshInvalidApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REFRESH-004',
        channelId: 'CH-001'
      });

      // Create a token with wrong secret
      const invalidRefreshToken = jwt.sign(
        {
          sub: app.clientId,
          jti: 'test-jti-refresh-invalid',
          applicationName: app.applicationName,
          financialId: app.financialId,
          channelId: app.channelId,
          allowedTools: [],
          allowedApis: [],
          isDeveloperPortalAPIsEnabled: false,
          type: 'refresh'
        },
        'wrong-secret',
        { expiresIn: '7d' }
      );

      // Attempt to refresh should fail
      await expect(
        tokenService.refreshAccessToken(invalidRefreshToken)
      ).rejects.toThrow('invalid signature');
    });

    it('should maintain 3Scale info in refreshed token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'Refresh3ScaleApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REFRESH-005',
        channelId: 'CH-001',
        isDeveloperPortalAPIsEnabled: true,
        threeScaleClientId: '3scale-id-refresh',
        threeScaleClientSecret: '3scale-secret-refresh'
      });

      // Generate token pair
      const tokens = await tokenService.generateTokenPair(app);

      // Refresh access token
      const newAccessToken = await tokenService.refreshAccessToken(
        tokens.refreshToken
      );

      // Verify 3Scale info is maintained
      const newPayload = await tokenService.verifyAccessToken(newAccessToken);
      expect(newPayload.isDeveloperPortalAPIsEnabled).toBe(true);
      expect(newPayload.threeScaleClientId).toBe('3scale-id-refresh');
      expect((newPayload as any).threeScaleClientSecret).toBeUndefined(); // NEVER in token
    });
  });

  describe('revokeToken', () => {
    it('should revoke access token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeAccessApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-ACCESS',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);

      // Revoke access token
      const result = await tokenService.revokeToken(tokens.accessToken);

      expect(result.tokenType).toBe('access');
      expect(result.jti).toBeDefined();

      // Check if token is in revoked list
      const isRevoked = await tokenService.isTokenRevoked(result.jti);
      expect(isRevoked).toBe(true);

      // Verify token should now fail
      await expect(
        tokenService.verifyAccessToken(tokens.accessToken)
      ).rejects.toThrow('Token has been revoked');
    });

    it('should revoke refresh token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeRefreshApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-REFRESH',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);
      const payload = await tokenService.verifyRefreshToken(
        tokens.refreshToken
      );

      // Revoke refresh token
      const result = await tokenService.revokeToken(tokens.refreshToken);

      expect(result.tokenType).toBe('refresh');

      // Check if token is marked as revoked in RefreshToken collection
      const storedToken = await RefreshToken.findOne({ jti: payload.jti });
      expect(storedToken?.isRevoked).toBe(true);

      // Check if token is in revoked list
      const isRevoked = await tokenService.isTokenRevoked(result.jti);
      expect(isRevoked).toBe(true);
    });

    it('should store revocation with reason', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeReasonApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-REASON',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);
      const reason = 'Security incident';

      await tokenService.revokeToken(tokens.accessToken, reason);

      const payload = jwt.decode(tokens.accessToken) as any;
      const revokedToken = await RevokedToken.findOne({ jti: payload.jti });

      expect(revokedToken).not.toBeNull();
      expect(revokedToken?.reason).toBe(reason);
    });

    it('should handle revoking already revoked token', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeDoubleApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-DOUBLE',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);

      // Revoke once
      await tokenService.revokeToken(tokens.accessToken);

      // Revoke again - should not throw error
      const result = await tokenService.revokeToken(tokens.accessToken);
      expect(result.jti).toBeDefined();
    });

    it('should set correct expiresAt for TTL cleanup', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeTTLApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-TTL',
        channelId: 'CH-001'
      });

      const tokens = await tokenService.generateTokenPair(app);
      await tokenService.revokeToken(tokens.accessToken);

      const payload = jwt.decode(tokens.accessToken) as any;
      const revokedToken = await RevokedToken.findOne({ jti: payload.jti });

      expect(revokedToken).not.toBeNull();
      expect(revokedToken?.expiresAt).toBeInstanceOf(Date);

      // expiresAt should match the token's exp claim
      const expectedExpiry = new Date(payload.exp * 1000);
      expect(revokedToken?.expiresAt.getTime()).toBe(expectedExpiry.getTime());
    });
  });

  describe('revokeAllTokensForClient', () => {
    it('should revoke all tokens for a client', async () => {
      const app = await applicationService.createApplication({
        applicationName: 'RevokeAllApp',
        description: 'Test',
        clientSecret: 'secret',
        financialId: 'FIN-REVOKE-ALL',
        channelId: 'CH-001'
      });

      // Generate multiple token pairs
      await tokenService.generateTokenPair(app);
      await tokenService.generateTokenPair(app);
      await tokenService.generateTokenPair(app);

      // Revoke all tokens
      const count = await tokenService.revokeAllTokensForClient(
        app.clientId,
        'Test cleanup'
      );

      expect(count).toBe(3);

      // All refresh tokens should be revoked
      const activeTokens = await RefreshToken.countDocuments({
        clientId: app.clientId,
        isRevoked: false
      });

      expect(activeTokens).toBe(0);
    });
  });
});
