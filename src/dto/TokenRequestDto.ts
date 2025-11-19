import { IsString, IsNotEmpty, Equals } from 'class-validator';

export class TokenRequestDto {
  @Equals('client_credentials', {
    message: 'grant_type must be "client_credentials"'
  })
  grant_type!: string;

  @IsString()
  @IsNotEmpty()
  client_id!: string;

  @IsString()
  @IsNotEmpty()
  client_secret!: string;
}
