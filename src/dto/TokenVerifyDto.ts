import { IsString, IsNotEmpty } from 'class-validator';

export class TokenVerifyDto {
  @IsString()
  @IsNotEmpty()
  token!: string;
}
