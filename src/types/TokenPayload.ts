export interface TokenPayload {
  sub: string; // Subject (clientId)
  jti: string; // JWT ID (unique identifier)
  applicationName: string;
  financialId: string;
  channelId: string;
  allowedTools: string[];
  allowedApis: string[];
  isDeveloperPortalAPIsEnabled: boolean;
  threeScaleClientId?: string; // 3Scale client ID (NOT the secret)
  iat: number; // Issued at
  exp: number; // Expires at
  type: 'access' | 'refresh';
}
