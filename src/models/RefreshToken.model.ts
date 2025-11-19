import { Schema, model, HydratedDocument } from 'mongoose';

export interface IRefreshToken {
  jti: string; // JWT ID (unique identifier)
  clientId: string; // Reference to application
  token: string; // Hashed refresh token
  expiresAt: Date;
  isRevoked: boolean;
  createdAt: Date;
}

const refreshTokenSchema = new Schema<IRefreshToken>(
  {
    jti: { type: String, required: true, unique: true, index: true },
    clientId: { type: String, required: true, index: true },
    token: { type: String, required: true },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 } // TTL index - MongoDB auto-deletes after this date
    },
    isRevoked: { type: Boolean, default: false }
  },
  { timestamps: true }
);

export type RefreshTokenDocument = HydratedDocument<IRefreshToken>;
export const RefreshToken = model<IRefreshToken>('RefreshToken', refreshTokenSchema);
