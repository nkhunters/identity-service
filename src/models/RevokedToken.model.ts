import { Schema, model, HydratedDocument } from 'mongoose';

export interface IRevokedToken {
  jti: string; // JWT ID from revoked token
  tokenType: 'access' | 'refresh'; // Type of token revoked
  clientId: string; // For logging/tracking purposes
  expiresAt: Date; // When token would naturally expire (for TTL)
  revokedAt: Date; // When it was revoked
  reason?: string; // Optional reason for revocation
}

const revokedTokenSchema = new Schema<IRevokedToken>(
  {
    jti: { type: String, required: true, unique: true, index: true },
    tokenType: { type: String, required: true, enum: ['access', 'refresh'] },
    clientId: { type: String, required: true, index: true },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 } // TTL index - MongoDB auto-deletes after this date
    },
    revokedAt: { type: Date, default: Date.now },
    reason: { type: String, required: false }
  },
  { timestamps: false } // Not needed since we have revokedAt
);

// Compound index for efficient queries
revokedTokenSchema.index({ jti: 1, clientId: 1 });

export type RevokedTokenDocument = HydratedDocument<IRevokedToken>;
export const RevokedToken = model<IRevokedToken>('RevokedToken', revokedTokenSchema);
