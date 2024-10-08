import {
  IsArray,
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsString,
  ValidateNested,
} from 'class-validator';
import { UserRole } from '../entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { UserDto } from './user_response.dto';

export class SignupRequest {
  @IsNotEmpty()
  @ApiProperty()
  @IsString()
  username: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty()
  password: string;

  @IsNotEmpty()
  @ApiProperty()
  display_name: string;

  @IsNotEmpty()
  @ApiProperty()
  is_social: boolean;
}

export class SigninRequest {
  @IsNotEmpty()
  @IsString()
  @ApiProperty()
  username: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty()
  password: string;
}

export class JwtPayload {
  id: number;
  username: string;
  role: UserRole;
}

class SerializableVector3IntDto {
  @IsInt() x: number;
  @IsInt() y: number;
  @IsInt() z: number;
}

class SerializablePlacementDataDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SerializableVector3IntDto)
  OccupiedPositions: SerializableVector3IntDto[];

  @ValidateNested()
  @Type(() => SerializableVector3IntDto)
  gridPosition: SerializableVector3IntDto;

  @IsInt() Id: number;
  @IsInt() Level: number;
  @IsBoolean() IsUpdating: boolean;
  @IsInt() RemainingTime: number;
  @IsInt() RemainingResource: number;
}

class ResourcesDto {
  @IsInt() wood: number;
  @IsInt() stone: number;
  @IsInt() gold: number;
  @IsInt() gem: number;
}

class ConstructionCountDataDto {
  @IsInt() wall: number;
  @IsInt() archer: number;
  @IsInt() canon: number;
  @IsInt() ice: number;
  @IsInt() flame: number;
  @IsInt() electro: number;
  @IsInt() poison: number;
  @IsInt() air: number;
  @IsInt() villager: number;
  @IsInt() research: number;
  @IsInt() resourceWood: number;
  @IsInt() resourceStone: number;
  @IsInt() decoration: number;
  @IsInt() archerHeroConstruction: number;
  @IsInt() wizardHeroConstruction: number;
}

class InventoryDto {
  @IsInt() constructionId: number;
  @IsInt() amount: number;
  @IsInt() constructionLevel: number;
}

export class SaveRequestDto {
  @IsString()
  encryptedData: string;

  @IsString()
  nonce: string;
}

export class PlayerDataDto {
  @IsInt() hallLevel: number;
  @IsInt() currentDay: number;
  @IsInt() ranking: number;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SerializablePlacementDataDto)
  listPlacementData: SerializablePlacementDataDto[];

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => InventoryDto)
  inventoryData: InventoryDto[];

  @ValidateNested()
  @Type(() => ResourcesDto)
  resources: ResourcesDto;

  @ValidateNested()
  @Type(() => ConstructionCountDataDto)
  constructionCountData: ConstructionCountDataDto;

  @IsInt() lastSaveTime: number;
  @IsInt() lastClaimDailyChestTime: number;
  @IsInt() lastClaimDailyGemTime: number;

  user: UserDto;
}

export class UpdateRequest {
  @IsString()
  region: string;

  @IsString()
  display_name: string;
}
