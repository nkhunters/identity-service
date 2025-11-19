import { describe, it, expect, beforeEach } from 'vitest';
import { Container } from 'typedi';
import { EncryptionService } from '../../src/services/EncryptionService.js';

describe('EncryptionService', () => {
  let encryptionService: EncryptionService;

  beforeEach(() => {
    encryptionService = Container.get(EncryptionService);
  });

  describe('hash', () => {
    it('should produce different hashes for same input', async () => {
      const password = 'test-password-123';
      const hash1 = await encryptionService.hash(password);
      const hash2 = await encryptionService.hash(password);

      expect(hash1).not.toBe(hash2);
      expect(hash1).toContain(':');
      expect(hash2).toContain(':');
    });

    it('should produce hash in salt:hash format', async () => {
      const password = 'test-password';
      const hash = await encryptionService.hash(password);
      const parts = hash.split(':');

      expect(parts).toHaveLength(2);
      expect(parts[0]).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(parts[1]).toHaveLength(128); // 64 bytes = 128 hex chars
    });
  });

  describe('verify', () => {
    it('should return true for correct password', async () => {
      const password = 'my-secret-password';
      const hash = await encryptionService.hash(password);
      const isValid = await encryptionService.verify(password, hash);

      expect(isValid).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      const password = 'correct-password';
      const hash = await encryptionService.hash(password);
      const isValid = await encryptionService.verify('wrong-password', hash);

      expect(isValid).toBe(false);
    });

    it('should return false for invalid hash format', async () => {
      const isValid = await encryptionService.verify('password', 'invalid-hash');

      expect(isValid).toBe(false);
    });
  });

  describe('encrypt', () => {
    it('should produce different encrypted outputs for same input', () => {
      const plainText = '3scale-secret-123';
      const encrypted1 = encryptionService.encrypt(plainText);
      const encrypted2 = encryptionService.encrypt(plainText);

      expect(encrypted1).not.toBe(encrypted2);
      expect(encrypted1).toContain(':');
      expect(encrypted2).toContain(':');
    });

    it('should produce encrypted text in iv:authTag:encrypted format', () => {
      const plainText = 'secret-data';
      const encrypted = encryptionService.encrypt(plainText);
      const parts = encrypted.split(':');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toHaveLength(32); // IV: 16 bytes = 32 hex chars
      expect(parts[1]).toHaveLength(32); // Auth tag: 16 bytes = 32 hex chars
      expect(parts[2].length).toBeGreaterThan(0); // Encrypted data
    });
  });

  describe('decrypt', () => {
    it('should correctly decrypt encrypted text', () => {
      const plainText = 'my-3scale-secret-key';
      const encrypted = encryptionService.encrypt(plainText);
      const decrypted = encryptionService.decrypt(encrypted);

      expect(decrypted).toBe(plainText);
    });

    it('should handle special characters', () => {
      const plainText = 'P@ssw0rd!#$%^&*()';
      const encrypted = encryptionService.encrypt(plainText);
      const decrypted = encryptionService.decrypt(encrypted);

      expect(decrypted).toBe(plainText);
    });

    it('should throw error for invalid encrypted text format', () => {
      expect(() => encryptionService.decrypt('invalid-format')).toThrow();
    });

    it('should throw error for tampered encrypted text', () => {
      const plainText = 'secret';
      const encrypted = encryptionService.encrypt(plainText);
      const tampered = encrypted.replace(/.$/, 'X'); // Change last character

      expect(() => encryptionService.decrypt(tampered)).toThrow();
    });
  });

  describe('end-to-end', () => {
    it('should handle hash and verify workflow', async () => {
      const passwords = ['password1', 'password2', 'password3'];

      for (const password of passwords) {
        const hash = await encryptionService.hash(password);
        expect(await encryptionService.verify(password, hash)).toBe(true);
        expect(await encryptionService.verify('wrong', hash)).toBe(false);
      }
    });

    it('should handle encrypt and decrypt workflow', () => {
      const secrets = ['secret1', 'secret2', 'secret3'];

      for (const secret of secrets) {
        const encrypted = encryptionService.encrypt(secret);
        const decrypted = encryptionService.decrypt(encrypted);
        expect(decrypted).toBe(secret);
      }
    });
  });
});
