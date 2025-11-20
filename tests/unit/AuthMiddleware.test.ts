import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { AuthMiddleware } from '../../src/middlewares/AuthMiddleware';
import { TokenService } from '../../src/services/TokenService';
import { TokenPayload } from '../../src/types/TokenPayload';

describe('AuthMiddleware', () => {
  let middleware: AuthMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let mockTokenService: Partial<TokenService>;

  beforeEach(() => {
    // Create mock token service
    mockTokenService = {
      verifyAccessToken: vi.fn()
    };

    // Create middleware with mocked service
    middleware = new AuthMiddleware(mockTokenService as TokenService);

    // Setup mock request
    mockRequest = {
      headers: {},
      path: '/test'
    };

    // Setup mock response with chainable methods
    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis()
    };

    // Setup mock next function
    mockNext = vi.fn();
  });

  describe('Missing or Invalid Authorization Header', () => {
    it('should reject request without authorization header', async () => {
      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'No authorization header provided'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject invalid authorization format', async () => {
      mockRequest.headers = { authorization: 'InvalidFormat token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authorization header must start with "Bearer "'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject empty token', async () => {
      mockRequest.headers = { authorization: 'Bearer ' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Token is required'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Valid Token', () => {
    it('should attach user payload to request for valid token', async () => {
      const mockPayload: TokenPayload = {
        sub: 'test-client-id',
        jti: 'test-jti',
        applicationName: 'TestApp',
        financialId: 'FIN-001',
        channelId: 'CH-001',
        allowedTools: ['tool1'],
        allowedApis: ['/api/test'],
        isDeveloperPortalAPIsEnabled: false,
        iat: Date.now() / 1000,
        exp: Date.now() / 1000 + 900,
        type: 'access'
      };

      // Mock TokenService.verifyAccessToken
      (mockTokenService.verifyAccessToken as any).mockResolvedValue(
        mockPayload
      );

      mockRequest.headers = { authorization: 'Bearer valid-token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as any).user).toEqual(mockPayload);
      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('Token Errors', () => {
    it('should reject expired token with expiredAt', async () => {
      const expiredError = new Error('Token expired');
      expiredError.name = 'TokenExpiredError';
      (expiredError as any).expiredAt = new Date('2024-01-01');

      (mockTokenService.verifyAccessToken as any).mockRejectedValue(
        expiredError
      );

      mockRequest.headers = { authorization: 'Bearer expired-token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Token expired',
        message: 'Your token has expired',
        expiredAt: new Date('2024-01-01')
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject token with invalid signature', async () => {
      const invalidError = new Error('Invalid signature');
      invalidError.name = 'JsonWebTokenError';

      (mockTokenService.verifyAccessToken as any).mockRejectedValue(
        invalidError
      );

      mockRequest.headers = { authorization: 'Bearer invalid-signature-token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Invalid token',
        message: 'Token is invalid or malformed'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject revoked token', async () => {
      const revokedError = new Error('Token has been revoked');

      (mockTokenService.verifyAccessToken as any).mockRejectedValue(
        revokedError
      );

      mockRequest.headers = { authorization: 'Bearer revoked-token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Token revoked',
        message: 'This token has been revoked'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle generic authentication errors', async () => {
      const genericError = new Error('Something went wrong');

      (mockTokenService.verifyAccessToken as any).mockRejectedValue(
        genericError
      );

      mockRequest.headers = { authorization: 'Bearer problematic-token' };

      await middleware.use(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication failed'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
