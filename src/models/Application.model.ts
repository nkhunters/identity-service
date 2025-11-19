import { Schema, model, HydratedDocument } from 'mongoose';

export interface IApplication {
  applicationName: string;
  description: string;
  clientId: string;
  clientSecret: string; // scrypt hashed (format: salt:hash)
  financialId: string;
  channelId: string;
  allowedTools: string[];
  allowedApis: string[];
  isDeveloperPortalAPIsEnabled: boolean;
  threeScaleClientId?: string;
  threeScaleClientSecret?: string; // AES-256-GCM encrypted (format: iv:authTag:encrypted)
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const applicationSchema = new Schema<IApplication>(
  {
    applicationName: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    clientId: { type: String, required: true, unique: true, index: true },
    clientSecret: { type: String, required: true },
    financialId: { type: String, required: true },
    channelId: { type: String, required: true },
    allowedTools: [{ type: String }],
    allowedApis: [{ type: String }],
    isDeveloperPortalAPIsEnabled: { type: Boolean, default: false },
    threeScaleClientId: { type: String, required: false },
    threeScaleClientSecret: { type: String, required: false },
    isActive: { type: Boolean, default: true }
  },
  { timestamps: true }
);

export type ApplicationDocument = HydratedDocument<IApplication>;
export const Application = model<IApplication>('Application', applicationSchema);
