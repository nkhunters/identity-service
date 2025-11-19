import { JsonController, Post, Body, HttpCode } from 'routing-controllers';
import { Inject, Service } from 'typedi';
import { ApplicationService } from '../services/ApplicationService.js';
import { TokenService } from '../services/TokenService.js';
import { TokenRequestDto } from '../dto/TokenRequestDto.js';
import { TokenRefreshDto } from '../dto/TokenRefreshDto.js';
import { TokenVerifyDto } from '../dto/TokenVerifyDto.js';
import { TokenRevokeDto } from '../dto/TokenRevokeDto.js';
import { logger } from '../utils/logger.js';

@Service()
@JsonController('/oauth')
export class OAuthController {
  constructor(
    @Inject() private applicationService: ApplicationService,
    @Inject() private tokenService: TokenService
  ) {}

  @Post('/token')
  @HttpCode(200)
  async token(@Body() dto: TokenRequestDto | TokenRefreshDto) {
    // Handle refresh_token grant type
    if (dto.grant_type === 'refresh_token') {
      const refreshDto = dto as TokenRefreshDto;
      logger.info('Token refresh request received');

      try {
        // Refresh access token
        const accessToken = await this.tokenService.refreshAccessToken(
          refreshDto.refresh_token
        );

        // Return OAuth2-compliant response (no new refresh_token)
        return {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 900 // 15 minutes in seconds
        };
      } catch (error: any) {
        logger.warn({ error: error.message }, 'Token refresh failed');
        throw new Error('Invalid or expired refresh token');
      }
    }

    // Handle client_credentials grant type
    if (dto.grant_type === 'client_credentials') {
      const credentialsDto = dto as TokenRequestDto;
      logger.info({ client_id: credentialsDto.client_id }, 'Token request received');

      // Validate credentials
      const application = await this.applicationService.validateCredentials(
        credentialsDto.client_id,
        credentialsDto.client_secret
      );

      if (!application || !application.isActive) {
        logger.warn({ client_id: credentialsDto.client_id }, 'Invalid credentials');
        throw new Error('Invalid client credentials');
      }

      // Generate token pair
      const tokens = await this.tokenService.generateTokenPair(application);

      // Return OAuth2-compliant response
      return {
        access_token: tokens.accessToken,
        token_type: 'Bearer',
        expires_in: 900, // 15 minutes in seconds
        refresh_token: tokens.refreshToken
      };
    }

    // Invalid grant type
    logger.warn({ grant_type: dto.grant_type }, 'Unsupported grant type');
    throw new Error('Unsupported grant type');
  }

  @Post('/verify')
  @HttpCode(200)
  async verify(@Body() dto: TokenVerifyDto) {
    try {
      // Verify the access token
      const payload = await this.tokenService.verifyAccessToken(dto.token);

      // Log successful verification
      logger.info(
        { clientId: payload.sub, jti: payload.jti },
        'Token verified successfully'
      );

      // Transform payload with ISO timestamps
      return {
        valid: true,
        payload: {
          clientId: payload.sub,
          jti: payload.jti,
          applicationName: payload.applicationName,
          financialId: payload.financialId,
          channelId: payload.channelId,
          allowedTools: payload.allowedTools,
          allowedApis: payload.allowedApis,
          isDeveloperPortalAPIsEnabled: payload.isDeveloperPortalAPIsEnabled,
          threeScaleClientId: payload.threeScaleClientId,
          issuedAt: new Date(payload.iat * 1000).toISOString(),
          expiresAt: new Date(payload.exp * 1000).toISOString()
        }
      };
    } catch (error: any) {
      // Handle TokenExpiredError
      if (error.name === 'TokenExpiredError') {
        logger.warn('Token verification failed: Token expired');
        return {
          valid: false,
          error: 'Token expired',
          expiredAt: new Date(error.expiredAt).toISOString()
        };
      }

      // Handle JsonWebTokenError (invalid signature, malformed token, etc.)
      if (error.name === 'JsonWebTokenError') {
        logger.warn({ message: error.message }, 'Token verification failed: Invalid token');
        return {
          valid: false,
          error: 'Invalid token',
          message: error.message
        };
      }

      // Handle invalid token type (refresh token instead of access token)
      if (error.message === 'Invalid token type') {
        logger.warn('Token verification failed: Invalid token type');
        return {
          valid: false,
          error: 'Invalid token type',
          message: 'Only access tokens can be verified at this endpoint'
        };
      }

      // Generic error handling
      logger.error({ error: error.message }, 'Token verification failed');
      return {
        valid: false,
        error: 'Token verification failed',
        message: error.message
      };
    }
  }

  @Post('/revoke')
  @HttpCode(200)
  async revoke(@Body() dto: TokenRevokeDto) {
    try {
      const result = await this.tokenService.revokeToken(dto.token, dto.reason);

      logger.info(
        {
          jti: result.jti,
          tokenType: result.tokenType,
          reason: dto.reason
        },
        'Token revoked via API'
      );

      return {
        success: true,
        message: 'Token revoked successfully',
        jti: result.jti,
        tokenType: result.tokenType
      };
    } catch (error: any) {
      logger.error({ error: error.message }, 'Token revocation failed');

      return {
        success: false,
        error: 'Token revocation failed',
        message: error.message
      };
    }
  }
}
