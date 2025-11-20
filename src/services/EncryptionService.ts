import { Service } from 'typedi';
import {
  scrypt,
  randomBytes,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv
} from 'crypto';
import { promisify } from 'util';
import { env } from '../config/env';

const scryptAsync = promisify(scrypt);

@Service()
export class EncryptionService {
  /**
   * Hash a password using scrypt (one-way, for clientSecret)
   * Format: salt:hash (both hex encoded)
   */
  async hash(plainText: string): Promise<string> {
    // Generate random 16-byte salt
    const salt = randomBytes(16).toString('hex');

    // Derive 64-byte key using scrypt
    const derivedKey = (await scryptAsync(plainText, salt, 64)) as Buffer;

    // Return in salt:hash format
    return `${salt}:${derivedKey.toString('hex')}`;
  }

  /**
   * Verify a password against a hash
   * Uses timing-safe comparison to prevent timing attacks
   */
  async verify(plainText: string, hashedWithSalt: string): Promise<boolean> {
    // Extract salt and stored hash
    const [salt, storedHash] = hashedWithSalt.split(':');

    if (!salt || !storedHash) {
      return false;
    }

    // Derive key with same salt
    const derivedKey = (await scryptAsync(plainText, salt, 64)) as Buffer;
    const storedHashBuffer = Buffer.from(storedHash, 'hex');

    // Timing-safe comparison
    return timingSafeEqual(derivedKey, storedHashBuffer);
  }

  /**
   * Encrypt plaintext using AES-256-GCM (reversible, for 3Scale clientSecret)
   * Format: iv:authTag:encrypted (all hex encoded)
   */
  encrypt(plainText: string): string {
    // Get encryption key from environment (32 bytes for AES-256)
    const encryptionKey = Buffer.from(env.ENCRYPTION_KEY, 'hex');

    // Generate random 16-byte IV
    const iv = randomBytes(16);

    // Create cipher
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);

    // Encrypt
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get authentication tag
    const authTag = cipher.getAuthTag().toString('hex');

    // Return in iv:authTag:encrypted format
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  /**
   * Decrypt ciphertext using AES-256-GCM
   * Validates authentication tag to prevent tampering
   */
  decrypt(encryptedText: string): string {
    // Extract components
    const [ivHex, authTagHex, encrypted] = encryptedText.split(':');

    if (!ivHex || !authTagHex || !encrypted) {
      throw new Error('Invalid encrypted text format');
    }

    // Get encryption key from environment
    const encryptionKey = Buffer.from(env.ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    // Create decipher
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(authTag);

    // Decrypt
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
