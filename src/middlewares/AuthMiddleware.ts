import { Request, Response, NextFunction } from 'express';
import { MiddlewareInterface } from 'routing-controllers';
import { Service } from 'typedi';
import { TokenService } from '../services/TokenService.js';
import { AuthenticatedRequest } from '../types/AuthenticatedRequest.js';
import { logger } from '../utils/logger.js';

/**
 * Authentication Middleware
 *
 * Extracts and verifies JWT tokens from Authorization header
 * Checks token revocation status
 * Attaches decoded payload to request.user for downstream use
 *
 * Returns 401 for:
 * - Missing authorization header
 * - Invalid Bearer token format
 * - Empty token
 * - Expired token
 * - Invalid signature
 * - Revoked token
 */
@Service()
export class AuthMiddleware implements MiddlewareInterface {
  constructor(
    private tokenService: TokenService
  ) {}

  async use(req: any, res: any, next?: (err?: any) => any): Promise<any> {
    try {
      // Extract Authorization header
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        logger.warn({ path: req.path }, 'No authorization header provided');
        res.status(401).json({
          error: 'Unauthorized',
          message: 'No authorization header provided'
        });
        return;
      }

      // Check if it's a Bearer token
      if (!authHeader.startsWith('Bearer ')) {
        logger.warn({ path: req.path }, 'Invalid authorization format');
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authorization header must start with "Bearer "'
        });
        return;
      }

      // Extract token
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix

      if (!token) {
        logger.warn({ path: req.path }, 'Empty token provided');
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Token is required'
        });
        return;
      }

      // Verify token signature and expiration
      // This also checks revocation status internally
      const payload = await this.tokenService.verifyAccessToken(token);

      // Attach payload to request
      (req as AuthenticatedRequest).user = payload;

      logger.debug(
        {
          clientId: payload.sub,
          jti: payload.jti,
          path: req.path
        },
        'Request authenticated'
      );

      if (next) next();
    } catch (error: any) {
      logger.warn(
        {
          path: req.path,
          error: error.message
        },
        'Authentication failed'
      );

      // Handle specific JWT errors
      if (error.name === 'TokenExpiredError') {
        res.status(401).json({
          error: 'Token expired',
          message: 'Your token has expired',
          expiredAt: error.expiredAt
        });
        return;
      }

      if (error.name === 'JsonWebTokenError') {
        res.status(401).json({
          error: 'Invalid token',
          message: 'Token is invalid or malformed'
        });
        return;
      }

      if (error.message === 'Token has been revoked') {
        res.status(401).json({
          error: 'Token revoked',
          message: 'This token has been revoked'
        });
        return;
      }

      // Generic authentication error
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication failed'
      });
    }
  }
}
