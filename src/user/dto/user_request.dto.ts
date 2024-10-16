import {
  IsArray,
  IsBoolean,
  IsNumber,
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
  @IsNumber() x: number;
  @IsNumber() y: number;
  @IsNumber() z: number;
}

class SerializablePlacementDataDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SerializableVector3IntDto)
  OccupiedPositions: SerializableVector3IntDto[];

  @ValidateNested()
  @Type(() => SerializableVector3IntDto)
  gridPosition: SerializableVector3IntDto;

  @IsNumber() Id: number;
  @IsNumber() Level: number;
  @IsBoolean() IsUpdating: boolean;
  @IsNumber() RemainingTime: number;
  @IsNumber() RemainingResource: number;
}

class ResourcesDto {
  @IsNumber() wood: number;
  @IsNumber() stone: number;
  @IsNumber() gold: number;
  @IsNumber() gem: number;
}

class ConstructionCountDataDto {
  @IsNumber() wall: number;
  @IsNumber() archer: number;
  @IsNumber() canon: number;
  @IsNumber() ice: number;
  @IsNumber() flame: number;
  @IsNumber() electro: number;
  @IsNumber() poison: number;
  @IsNumber() air: number;
  @IsNumber() villager: number;
  @IsNumber() research: number;
  @IsNumber() resourceWood: number;
  @IsNumber() resourceStone: number;
  @IsNumber() decoration: number;
  @IsNumber() archerHeroConstruction: number;
  @IsNumber() wizardHeroConstruction: number;
}

class ResearchBonusDto {
  @IsNumber() civilianHpBonus: number;
  @IsNumber() wallHpBonus: number;
  @IsNumber() towerHpBonus: number;
  @IsNumber() towerAttackBonus: number;
  @IsNumber() towerAttackSpeedBonus: number;
  @IsNumber() towerAttackRangeBonus: number;
  @IsNumber() heroAttackBonus: number;
  @IsNumber() heroAttackSpeedBonus: number;
  @IsNumber() decreaseBuildTimeBonus: number;
}

class InventoryDto {
  @IsNumber() constructionId: number;
  @IsNumber() amount: number;
  @IsNumber() constructionLevel: number;
}

export class SaveRequestDto {
  @IsString()
  encryptedData: string;

  @IsString()
  nonce: string;
}

export class PlayerDataDto {
  @IsNumber() hallLevel: number;
  @IsNumber() currentDay: number;
  @IsNumber() ranking: number;

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

  @ValidateNested()
  @Type(() => ResearchBonusDto)
  researchBonus: ResearchBonusDto;

  @IsNumber() lastSaveTime: number;
  @IsNumber() lastClaimDailyChestTime: number;
  @IsNumber() lastClaimDailyGemTime: number;

  user: UserDto;
}

export class UpdateRequest {
  @IsString()
  region: string;

  @IsString()
  display_name: string;
}
