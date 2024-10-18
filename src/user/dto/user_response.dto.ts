import { IsEnum, IsNotEmpty, IsNumber, IsString } from 'class-validator';
import { UserRole } from '../entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';
import { PlayerDataDto } from './user_request.dto';
export class DefaultResponse {
  status: number;
  message: string;
}

export class AuthResponse {
  @ApiProperty()
  access_token: string;

  @ApiProperty()
  expires_in: number;
}

export class UserDto {
  @IsNotEmpty()
  @IsNumber()
  id: number;

  @IsNotEmpty()
  @IsString()
  username: string;

  @IsNotEmpty()
  @IsEnum(UserRole)
  role: UserRole;

  @IsString()
  region: string;

  is_social: boolean;
  is_guest: boolean;

  @IsString()
  display_name: string;

  playerData: PlayerDataDto;

  createdAt: Date;
  updatedAt: Date;
}

export class RankDto {
  playerPlace: number;
  playerData: PlayerDataDto;
  data: PlayerDataDto[];
}