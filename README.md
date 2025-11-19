# OAuth2 Identity Service

A production-ready OAuth2 Identity Service implementing the Client Credentials flow for microservice-to-microservice authentication and authorization.

## Features

- **Application Onboarding**: Generate unique clientId and securely hashed clientSecret
- **OAuth2 Token Generation**: Client credentials flow with JWT access and refresh tokens
- **Token Management**: Verification, refresh, and revocation capabilities
- **Authorization**: Fine-grained control via allowedTools and allowedApis
- **3Scale Integration**: Optional Developer Portal API access with encrypted credentials
- **Secure Credential Storage**: crypto.scrypt for hashing, AES-256-GCM for encryption
- **Token Blacklist**: MongoDB-based revocation with automatic TTL cleanup

## Technology Stack

- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js with routing-controllers
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT (jsonwebtoken)
- **Validation**: class-validator
- **Logging**: Pino
- **Testing**: Vitest
- **DI Container**: TypeDI

## Prerequisites

- Node.js v18+ (recommended v18.18.0+)
- MongoDB (local or remote instance)
- npm or yarn

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd identity-service
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```

4. **Generate encryption key**
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

5. **Update .env file with your configuration**
   ```env
   PORT=3000
   NODE_ENV=development
   MONGODB_URI=mongodb://localhost:27017/identity-service
   JWT_ACCESS_SECRET=your-secret-access-key
   JWT_REFRESH_SECRET=your-secret-refresh-key
   JWT_ACCESS_EXPIRATION=15m
   JWT_REFRESH_EXPIRATION=7d
   ENCRYPTION_KEY=<generated-64-character-hex-key>
   ```

## Running the Application

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm run build
npm start
```

## Project Structure

```
src/
├── index.ts                    # Server bootstrap
├── config/
│   ├── database.ts            # MongoDB connection with retry logic
│   └── env.ts                 # Environment variable validation
├── models/                    # Mongoose schemas (to be added in PRP 3)
├── controllers/               # HTTP controllers (to be added in PRP 6)
├── services/                  # Business logic (to be added in PRPs 2-5)
├── middlewares/               # Auth & authorization (to be added in PRP 6)
├── dto/                       # Data transfer objects (to be added in PRP 7)
├── types/                     # TypeScript types
└── utils/
    ├── logger.ts              # Pino logger configuration
    └── errors.ts              # Custom error classes
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| PORT | Server port | No | 3000 |
| NODE_ENV | Environment (development/production) | No | development |
| MONGODB_URI | MongoDB connection string | Yes | - |
| JWT_ACCESS_SECRET | Secret for access token signing | Yes | - |
| JWT_REFRESH_SECRET | Secret for refresh token signing | Yes | - |
| JWT_ACCESS_EXPIRATION | Access token expiration time | No | 15m |
| JWT_REFRESH_EXPIRATION | Refresh token expiration time | No | 7d |
| ENCRYPTION_KEY | 64-character hex key for AES-256 encryption | Yes | - |

## API Endpoints

### Application Management
- ✅ `POST /applications` - Create application (onboarding)
- ✅ `GET /applications/:clientId` - Get application details
- ⏳ `GET /applications/:clientId/3scale-credentials` - Get 3Scale credentials (authenticated)

### OAuth2 Endpoints
- ✅ `POST /oauth/token` - Generate tokens (supports both `client_credentials` and `refresh_token` grants)
- ✅ `POST /oauth/verify` - Verify access token
- ⏳ `POST /oauth/revoke` - Revoke token

**Legend**: ✅ Implemented | ⏳ Planned

## Testing

### Run all tests
```bash
npm test
```

### Run tests with coverage
```bash
npm run test:coverage
```

## Security Considerations

- **ClientSecret**: Hashed using crypto.scrypt with 64-byte key derivation and random salt
- **3Scale Credentials**: Encrypted using AES-256-GCM with random IV
- **JWT Tokens**: Strong secrets (256+ bits), short access token expiration (15 min)
- **Token Revocation**: MongoDB blacklist with TTL indexes for automatic cleanup
- **Input Validation**: All inputs validated using class-validator
- **Environment Variables**: Validated on startup (fail-fast approach)

## Development

### Build
```bash
npm run build
```

### Type Checking
```bash
npx tsc --noEmit
```

### Code Style
- Follow KISS (Keep It Simple, Stupid) principle
- Follow YAGNI (You Aren't Gonna Need It) principle
- Single Responsibility: Each function/class has one clear purpose
- Dependency Inversion: Use abstractions and dependency injection
- Keep files under 500 lines
- Comment non-obvious code

## Implementation Status

### ✅ Completed

**PRP 1: Base Setup & Configuration**
- [x] Project structure and dependencies
- [x] Environment configuration with validation
- [x] MongoDB connection with retry logic
- [x] Logger setup (Pino)
- [x] Custom error classes
- [x] Server bootstrap with routing-controllers
- [x] TypeScript configuration
- [x] Vitest testing setup

**PRP 2: Encryption Service**
- [x] Scrypt-based password hashing with salt
- [x] Timing-safe password verification
- [x] AES-256-GCM encryption/decryption
- [x] 13 comprehensive unit tests

**PRP 3: Application Onboarding**
- [x] Application model with MongoDB schema
- [x] ClientId generation (8-char nanoid)
- [x] ClientSecret hashing
- [x] 3Scale credentials encryption
- [x] Application service with validation
- [x] Application controller endpoints
- [x] Unit and integration tests

**PRP 4: OAuth2 Token Generation**
- [x] JWT access and refresh tokens
- [x] RefreshToken model with TTL index
- [x] Token generation service
- [x] POST /oauth/token endpoint (client_credentials)
- [x] OAuth2-compliant response format
- [x] 3Scale integration support
- [x] Unit and integration tests

**PRP 5: Token Verification**
- [x] verifyAccessToken() service method
- [x] POST /oauth/verify endpoint
- [x] JWT signature verification
- [x] Token type validation
- [x] Graceful error handling (expired, invalid, malformed)
- [x] ISO timestamp conversion
- [x] Unit and integration tests

**PRP 6: Token Refresh**
- [x] refreshAccessToken() service method
- [x] POST /oauth/token with refresh_token grant
- [x] Multi-layer validation (JWT, database, revocation, expiration)
- [x] Timing-safe hash comparison
- [x] Generate new access token with same permissions
- [x] OAuth2-compliant response
- [x] Unit and integration tests

### 🚧 Next Up
- [ ] Token Revocation (PRP 7)
- [ ] Authorization Middleware (PRP 8)
- [ ] 3Scale Integration Endpoint (PRP 9)

## Contributing

See [PLANNING.md](./PLANNING.md) for architecture details and development guidelines.

See [TASK.md](./TASK.md) for current tasks and progress tracking.

See [CLAUDE.md](./CLAUDE.md) for AI-assisted development guidelines.

## License

ISC

## Links

- [OAuth2 Client Credentials Flow](https://www.scalekit.com/blog/client-credentials-flow-oauth)
- [routing-controllers Documentation](https://github.com/typestack/routing-controllers)
- [Mongoose TypeScript Guide](https://mongoosejs.com/docs/typescript.html)
- [JWT Best Practices](https://developer.okta.com/blog/2018/06/06/node-api-oauth-client-credentials)

---

**Status**: PRPs 1-6 Complete - Core OAuth2 functionality ready (token generation, verification, refresh)
