import { Request } from 'express';
import { TokenPayload } from './TokenPayload';

/**
 * Extended Express Request interface with authenticated user payload
 *
 * Used by AuthMiddleware to attach decoded JWT payload to request object
 * Controllers can then access request.user for authorization checks
 */
export interface AuthenticatedRequest extends Request {
  user?: TokenPayload; // Decoded JWT payload (undefined if not authenticated)
}
