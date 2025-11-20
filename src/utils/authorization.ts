import { AuthenticatedRequest } from '../types/AuthenticatedRequest';
import { ForbiddenError } from './errors';
import { logger } from './logger';

/**
 * Authorization Helper Functions
 *
 * These functions check if authenticated users have required permissions
 * based on allowedTools and allowedApis in their JWT payload
 *
 * All functions throw ForbiddenError (403) if permissions are insufficient
 */

/**
 * Require ALL specified tools
 *
 * @param req - Authenticated request with user payload
 * @param tools - Array of required tool identifiers
 * @throws ForbiddenError if user lacks any required tool
 */
export function requireTools(req: AuthenticatedRequest, tools: string[]): void {
  if (!req.user) {
    throw new ForbiddenError('Not authenticated');
  }

  const userTools = req.user.allowedTools || [];
  const hasAllTools = tools.every((tool) => userTools.includes(tool));

  if (!hasAllTools) {
    logger.warn(
      {
        clientId: req.user.sub,
        requiredTools: tools,
        userTools
      },
      'Insufficient tool permissions'
    );

    throw new ForbiddenError(
      `Required tools: ${tools.join(', ')}. You have: ${userTools.join(', ')}`
    );
  }
}

/**
 * Require ALL specified APIs
 *
 * @param req - Authenticated request with user payload
 * @param apis - Array of required API endpoints
 * @throws ForbiddenError if user lacks any required API
 */
export function requireApis(req: AuthenticatedRequest, apis: string[]): void {
  if (!req.user) {
    throw new ForbiddenError('Not authenticated');
  }

  const userApis = req.user.allowedApis || [];
  const hasAllApis = apis.every((api) => userApis.includes(api));

  if (!hasAllApis) {
    logger.warn(
      {
        clientId: req.user.sub,
        requiredApis: apis,
        userApis
      },
      'Insufficient API permissions'
    );

    throw new ForbiddenError(
      `Required APIs: ${apis.join(', ')}. You have: ${userApis.join(', ')}`
    );
  }
}

/**
 * Require AT LEAST ONE of specified tools
 *
 * @param req - Authenticated request with user payload
 * @param tools - Array of tool identifiers (user needs at least one)
 * @throws ForbiddenError if user has none of the required tools
 */
export function requireAnyTool(
  req: AuthenticatedRequest,
  tools: string[]
): void {
  if (!req.user) {
    throw new ForbiddenError('Not authenticated');
  }

  const userTools = req.user.allowedTools || [];
  const hasAnyTool = tools.some((tool) => userTools.includes(tool));

  if (!hasAnyTool) {
    logger.warn(
      {
        clientId: req.user.sub,
        requiredTools: tools,
        userTools
      },
      'No matching tool permissions'
    );

    throw new ForbiddenError(`Required at least one of: ${tools.join(', ')}`);
  }
}

/**
 * Require AT LEAST ONE of specified APIs
 *
 * @param req - Authenticated request with user payload
 * @param apis - Array of API endpoints (user needs at least one)
 * @throws ForbiddenError if user has none of the required APIs
 */
export function requireAnyApi(req: AuthenticatedRequest, apis: string[]): void {
  if (!req.user) {
    throw new ForbiddenError('Not authenticated');
  }

  const userApis = req.user.allowedApis || [];
  const hasAnyApi = apis.some((api) => userApis.includes(api));

  if (!hasAnyApi) {
    logger.warn(
      {
        clientId: req.user.sub,
        requiredApis: apis,
        userApis
      },
      'No matching API permissions'
    );

    throw new ForbiddenError(`Required at least one of: ${apis.join(', ')}`);
  }
}
