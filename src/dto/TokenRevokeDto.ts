import { IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class TokenRevokeDto {
  @IsString()
  @IsNotEmpty()
  token!: string; // Can be access or refresh token

  @IsString()
  @IsOptional()
  token_type_hint?: 'access_token' | 'refresh_token'; // Optional hint for optimization

  @IsString()
  @IsOptional()
  reason?: string; // Optional reason for revocation
}
