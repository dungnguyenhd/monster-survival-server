import { IsEnum, IsNotEmpty, IsNumber, IsString } from 'class-validator';
import { UserRole } from '../entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';
import { PlayerDataEntity } from '../entities/user-save.entity';
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
  display_name: string;

  playerData: PlayerDataDto;

  createdAt: Date;
  updatedAt: Date;
}
