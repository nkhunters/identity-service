import { IsString, IsNotEmpty, Equals } from 'class-validator';

export class TokenRefreshDto {
  @Equals('refresh_token', {
    message: 'grant_type must be "refresh_token"'
  })
  grant_type!: string;

  @IsString()
  @IsNotEmpty()
  refresh_token!: string;
}
