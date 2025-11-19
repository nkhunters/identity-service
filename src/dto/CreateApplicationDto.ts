import { IsString, IsNotEmpty, IsArray, IsBoolean, IsOptional, ValidateIf } from 'class-validator';

export class CreateApplicationDto {
  @IsString()
  @IsNotEmpty()
  applicationName!: string;

  @IsString()
  @IsNotEmpty()
  description!: string;

  @IsString()
  @IsNotEmpty()
  clientSecret!: string;

  @IsString()
  @IsNotEmpty()
  financialId!: string;

  @IsString()
  @IsNotEmpty()
  channelId!: string;

  @IsArray()
  @IsOptional()
  allowedTools?: string[];

  @IsArray()
  @IsOptional()
  allowedApis?: string[];

  @IsBoolean()
  @IsOptional()
  isDeveloperPortalAPIsEnabled?: boolean;

  // Conditional validation: required if isDeveloperPortalAPIsEnabled is true
  @ValidateIf((o) => o.isDeveloperPortalAPIsEnabled === true)
  @IsString()
  @IsNotEmpty()
  threeScaleClientId?: string;

  @ValidateIf((o) => o.isDeveloperPortalAPIsEnabled === true)
  @IsString()
  @IsNotEmpty()
  threeScaleClientSecret?: string;
}
