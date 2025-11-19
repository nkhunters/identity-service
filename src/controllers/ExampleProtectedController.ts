import { JsonController, Get, UseBefore, Req } from 'routing-controllers';
import { Service } from 'typedi';
import { AuthMiddleware } from '../middlewares/AuthMiddleware.js';
import { AuthenticatedRequest } from '../types/AuthenticatedRequest.js';
import { requireTools, requireApis } from '../utils/authorization.js';

/**
 * Example Protected Controller
 *
 * Demonstrates different authorization patterns:
 * - Tool-based authorization
 * - API-based authorization
 * - Public endpoints for authenticated users
 *
 * All endpoints require authentication (AuthMiddleware)
 * Some endpoints require specific permissions (requireTools/requireApis)
 */
@Service()
@JsonController('/protected')
@UseBefore(AuthMiddleware) // Apply to all endpoints in this controller
export class ExampleProtectedController {
  /**
   * Tool-restricted endpoint
   * Requires user to have BOTH tool1 AND tool2
   */
  @Get('/tool-restricted')
  async toolRestricted(@Req() request: AuthenticatedRequest) {
    // Require specific tools
    requireTools(request, ['tool1', 'tool2']);

    return {
      message: 'You have access to tool1 and tool2',
      user: {
        clientId: request.user!.sub,
        applicationName: request.user!.applicationName,
        allowedTools: request.user!.allowedTools,
        allowedApis: request.user!.allowedApis
      }
    };
  }

  /**
   * API-restricted endpoint
   * Requires user to have access to /api/users
   */
  @Get('/api-restricted')
  async apiRestricted(@Req() request: AuthenticatedRequest) {
    // Require specific APIs
    requireApis(request, ['/api/users']);

    return {
      message: 'You have access to /api/users',
      user: {
        clientId: request.user!.sub,
        applicationName: request.user!.applicationName,
        allowedTools: request.user!.allowedTools,
        allowedApis: request.user!.allowedApis
      }
    };
  }

  /**
   * Public endpoint for authenticated users
   * No specific permissions required, just authentication
   */
  @Get('/public-for-authenticated')
  async publicForAuthenticated(@Req() request: AuthenticatedRequest) {
    // No specific permissions required, just authentication
    return {
      message: 'You are authenticated',
      clientId: request.user!.sub,
      applicationName: request.user!.applicationName,
      financialId: request.user!.financialId,
      channelId: request.user!.channelId,
      isDeveloperPortalAPIsEnabled: request.user!.isDeveloperPortalAPIsEnabled
    };
  }
}
