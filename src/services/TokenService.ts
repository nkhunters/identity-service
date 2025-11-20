import { Service } from 'typedi';
import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { ApplicationDocument } from '../models/Application.model';
import { RefreshToken } from '../models/RefreshToken.model';
import { RevokedToken } from '../models/RevokedToken.model';
import { EncryptionService } from './EncryptionService';
import { TokenPayload } from '../types/TokenPayload';
import { JwtTokens } from '../types/JwtTokens';
import { logger } from '../utils/logger';
import { env } from '../config/env';

@Service()
export class TokenService {
  constructor(private encryptionService: EncryptionService) {}

  async generateTokenPair(
    application: ApplicationDocument
  ): Promise<JwtTokens> {
    // Generate unique JTI for both tokens
    const accessJti = uuidv4();
    const refreshJti = uuidv4();

    // Create base payload with application details
    const basePayload = {
      sub: application.clientId,
      applicationName: application.applicationName,
      financialId: application.financialId,
      channelId: application.channelId,
      allowedTools: application.allowedTools,
      allowedApis: application.allowedApis,
      isDeveloperPortalAPIsEnabled: application.isDeveloperPortalAPIsEnabled,
      threeScaleClientId: application.threeScaleClientId // Include 3Scale client ID (NOT secret)
    };

    // Sign access token with short expiration
    const accessToken = jwt.sign(
      { ...basePayload, jti: accessJti, type: 'access' },
      env.JWT_ACCESS_SECRET,
      { expiresIn: env.JWT_ACCESS_EXPIRATION } as SignOptions
    );

    // Sign refresh token with long expiration
    const refreshToken = jwt.sign(
      { ...basePayload, jti: refreshJti, type: 'refresh' },
      env.JWT_REFRESH_SECRET,
      { expiresIn: env.JWT_REFRESH_EXPIRATION } as SignOptions
    );

    // Calculate expiration date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    // Hash refresh token before storing
    const hashedRefreshToken = await this.encryptionService.hash(refreshToken);

    // Store refresh token in database
    await RefreshToken.create({
      jti: refreshJti,
      clientId: application.clientId,
      token: hashedRefreshToken,
      expiresAt,
      isRevoked: false
    });

    logger.info(
      {
        clientId: application.clientId,
        accessJti,
        refreshJti
      },
      'Token pair generated'
    );

    return { accessToken, refreshToken };
  }

  async verifyAccessToken(token: string): Promise<TokenPayload> {
    try {
      const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as TokenPayload;

      if (payload.type !== 'access') {
        throw new Error('Invalid token type');
      }

      // Check if token is revoked
      const isRevoked = await this.isTokenRevoked(payload.jti);
      if (isRevoked) {
        logger.warn({ jti: payload.jti }, 'Attempted use of revoked token');
        throw new Error('Token has been revoked');
      }

      return payload;
    } catch (error) {
      logger.error({ error }, 'Access token verification failed');
      throw error;
    }
  }

  async verifyRefreshToken(token: string): Promise<TokenPayload> {
    try {
      const payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as TokenPayload;

      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return payload;
    } catch (error) {
      logger.error({ error }, 'Refresh token verification failed');
      throw error;
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<string> {
    try {
      // Step 1: Verify refresh token JWT signature
      const payload = await this.verifyRefreshToken(refreshToken);

      logger.info(
        { jti: payload.jti, clientId: payload.sub },
        'Refresh token verified, checking database'
      );

      // Step 2: Query database for stored refresh token using jti
      const storedToken = await RefreshToken.findOne({ jti: payload.jti });

      // Step 3: Validate token exists
      if (!storedToken) {
        logger.warn(
          { jti: payload.jti },
          'Refresh token not found in database'
        );
        throw new Error('Refresh token not found');
      }

      // Step 4: Validate token is not revoked
      if (storedToken.isRevoked) {
        logger.warn(
          { jti: payload.jti, clientId: payload.sub },
          'Refresh token is revoked'
        );
        throw new Error('Refresh token has been revoked');
      }

      // Step 5: Validate token is not expired (database-level check)
      if (storedToken.expiresAt < new Date()) {
        logger.warn(
          { jti: payload.jti, expiresAt: storedToken.expiresAt },
          'Refresh token is expired'
        );
        throw new Error('Refresh token has expired');
      }

      // Step 6: Hash-compare provided token with stored hash (timing-safe)
      const isValid = await this.encryptionService.verify(
        refreshToken,
        storedToken.token
      );

      if (!isValid) {
        logger.warn({ jti: payload.jti }, 'Refresh token hash mismatch');
        throw new Error('Invalid refresh token');
      }

      // Step 7: Generate new access token with same permissions/context
      const accessJti = uuidv4();
      const accessToken = jwt.sign(
        {
          sub: payload.sub,
          jti: accessJti,
          type: 'access',
          applicationName: payload.applicationName,
          financialId: payload.financialId,
          channelId: payload.channelId,
          allowedTools: payload.allowedTools,
          allowedApis: payload.allowedApis,
          isDeveloperPortalAPIsEnabled: payload.isDeveloperPortalAPIsEnabled,
          threeScaleClientId: payload.threeScaleClientId
        },
        env.JWT_ACCESS_SECRET,
        { expiresIn: env.JWT_ACCESS_EXPIRATION } as SignOptions
      );

      logger.info(
        {
          clientId: payload.sub,
          refreshJti: payload.jti,
          newAccessJti: accessJti
        },
        'Access token refreshed successfully'
      );

      return accessToken;
    } catch (error) {
      logger.error({ error }, 'Token refresh failed');
      throw error;
    }
  }

  async isTokenRevoked(jti: string): Promise<boolean> {
    const revokedToken = await RevokedToken.findOne({ jti });
    return revokedToken !== null;
  }

  async revokeToken(
    token: string,
    reason?: string
  ): Promise<{ jti: string; tokenType: 'access' | 'refresh' }> {
    try {
      // Try to decode as access token first
      let payload: TokenPayload;
      let tokenType: 'access' | 'refresh';

      try {
        payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as TokenPayload;
        tokenType = 'access';
      } catch {
        // If access token verification fails, try refresh token
        payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as TokenPayload;
        tokenType = 'refresh';
      }

      // Check if token type in payload matches
      if (payload.type !== tokenType) {
        throw new Error('Token type mismatch');
      }

      // Check if already revoked
      const existingRevocation = await RevokedToken.findOne({
        jti: payload.jti
      });
      if (existingRevocation) {
        logger.info({ jti: payload.jti }, 'Token already revoked');
        return { jti: payload.jti, tokenType };
      }

      // Add to revoked tokens collection
      await RevokedToken.create({
        jti: payload.jti,
        tokenType,
        clientId: payload.sub,
        expiresAt: new Date(payload.exp * 1000), // Convert JWT exp to Date
        revokedAt: new Date(),
        reason
      });

      // If refresh token, also mark as revoked in RefreshToken collection
      if (tokenType === 'refresh') {
        await RefreshToken.updateOne({ jti: payload.jti }, { isRevoked: true });
      }

      logger.info(
        {
          jti: payload.jti,
          tokenType,
          clientId: payload.sub,
          reason
        },
        'Token revoked'
      );

      return { jti: payload.jti, tokenType };
    } catch (error: any) {
      logger.error({ error: error.message }, 'Token revocation failed');
      throw new Error('Invalid token or token already expired');
    }
  }

  async revokeAllTokensForClient(
    clientId: string,
    reason?: string
  ): Promise<number> {
    // Find all active refresh tokens for the client
    const refreshTokens = await RefreshToken.find({
      clientId,
      isRevoked: false
    });

    let revokedCount = 0;

    // Revoke each refresh token
    for (const rt of refreshTokens) {
      try {
        // Mark as revoked in RefreshToken collection
        await RefreshToken.updateOne({ jti: rt.jti }, { isRevoked: true });

        // Add to RevokedToken collection
        await RevokedToken.create({
          jti: rt.jti,
          tokenType: 'refresh',
          clientId,
          expiresAt: rt.expiresAt,
          revokedAt: new Date(),
          reason: reason || 'Bulk revocation'
        });

        revokedCount++;
      } catch (error) {
        logger.error({ jti: rt.jti, error }, 'Failed to revoke token');
      }
    }

    logger.info(
      { clientId, revokedCount, reason },
      'All tokens revoked for client'
    );

    return revokedCount;
  }
}
