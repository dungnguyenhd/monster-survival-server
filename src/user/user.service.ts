import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import {
  SigninRequest,
  SignupRequest,
  UpdateRequest,
} from './dto/user_request.dto';
import { EntityManager, MoreThan, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import {
  DUPLICATE_USERNAME,
  PASSWORD_INCORRECT,
  USER_NOT_FOUND,
  USERNAME_INCORRECT,
} from 'src/common/constants/error.constant';
import * as bcrypt from 'bcryptjs';
import { UserEntity, UserRole } from './entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import {
  AuthResponse,
  DefaultResponse,
  RankDto,
  UserDto,
} from './dto/user_response.dto';
import { PlayerDataEntity } from './entities/user-save.entity';
import * as crypto from 'crypto';
import * as aesjs from 'aes-js';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    @InjectRepository(PlayerDataEntity)
    private readonly playerDataRepository: Repository<PlayerDataEntity>,
    private configService: ConfigService,
    private jwtService: JwtService,
  ) {}

  async signup(signupRequest: SignupRequest): Promise<AuthResponse> {
    const { username, password, display_name } = signupRequest;
    const existUser = await this.userRepository.findOne({
      where: {
        username,
      },
    });

    if (existUser) throw new UnauthorizedException(DUPLICATE_USERNAME);

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const user = await this.userRepository.save({
      username: username,
      password: hash,
      display_name: display_name,
      role: UserRole.USER,
    });

    delete user.password;
    return this.generateToken(user.id, user.username, user.role);
  }

  async signin(signinRequest: SigninRequest): Promise<AuthResponse> {
    const { username, password } = signinRequest;
    const user = await this.userRepository.findOne({
      where: {
        username,
      },
    });
    if (!user) throw new UnauthorizedException(USERNAME_INCORRECT);

    const is_password_match = await bcrypt.compare(password, user.password);
    if (!is_password_match) throw new UnauthorizedException(PASSWORD_INCORRECT);

    return this.generateToken(user.id, user.username, user.role);
  }

  async connectAccount(userId: number, request: SignupRequest): Promise<UserDto> {
    const { username, password, display_name, is_social } = request;
    const existUser = await this.userRepository.findOne({
      where: {
        username,
      },
    });

    if (existUser) throw new UnauthorizedException(DUPLICATE_USERNAME);

    const updateUser = await this.userRepository.findOne({
      where: {
        id: userId,
      },
    });

    if (!updateUser) throw new UnauthorizedException(USERNAME_INCORRECT);

    updateUser.username = username;
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    updateUser.password = hash;
    updateUser.display_name = display_name;
    updateUser.is_guest = false;
    updateUser.is_social = is_social;
    return await this.userRepository.save(updateUser);
  }

  generateToken(id: number, username: string, role: number) {
    const payload = {
      id: id,
      username,
      role,
    };
    const expireIn = this.configService.get('TOKEN_EXPIRES_TIME');
    const token = this.jwtService.sign(payload);

    return {
      access_token: token,
      expires_in: expireIn,
    };
  }

  generateDynamicKey(userId: string, nonce: string): Buffer {
    const hmac = crypto.createHmac(
      'sha256',
      this.configService.get('SECRETKEY'),
    );
    const combinedData = userId + nonce;
    const hash = hmac.update(combinedData).digest(); // Trả về mảng byte
    return hash; // Đây sẽ là 32 bytes
  }

  // Decrypt data using dynamic key and return the decrypted string
  decryptData(encryptedData: string, dynamicKey: Buffer): string {
    const encryptedBytes = Buffer.from(encryptedData, 'base64');
    const iv = encryptedBytes.slice(0, 16); // Đảm bảo iv có độ dài 16 bytes
    const data = encryptedBytes.slice(16);
    const aesCbc = new aesjs.ModeOfOperation.cbc(dynamicKey, iv);
    const decryptedBytes = aesCbc.decrypt(data);

    // Remove padding added during encryption
    const unpaddedBytes = aesjs.padding.pkcs7.strip(decryptedBytes);
    const decryptedText = aesjs.utils.utf8.fromBytes(unpaddedBytes);

    // Log and return decrypted text
    console.log('Decrypted Text:', decryptedText);
    return decryptedText.trim();
  }

  // Save player data after decrypting and parsing it
  async savePlayerData(userId: number, encryptedData: string, nonce: string) {
    try {
      const dynamicKey = this.generateDynamicKey(userId.toString(), nonce);
      const decryptedData = this.decryptData(
        encryptedData,
        Buffer.from(dynamicKey),
      );

      // Check if decryptedData is a valid JSON string
      const sanitizedData = this.sanitizeJsonString(decryptedData);

      // Parse the sanitized JSON string
      const playerDataDto = JSON.parse(sanitizedData);

      // Proceed with saving player data to the repository
      let playerDataEntity = await this.playerDataRepository.findOne({
        where: { userId },
      });

      if (!playerDataEntity) {
        playerDataEntity = new PlayerDataEntity();
      }

      playerDataEntity.userId = userId;
      playerDataEntity.hallLevel = playerDataDto.hallLevel;
      playerDataEntity.currentDay = playerDataDto.currentDay;
      playerDataEntity.listPlacementData = playerDataDto.listPlacementData;
      playerDataEntity.inventoryData = playerDataDto.inventoryData;
      playerDataEntity.resources = playerDataDto.resources;
      playerDataEntity.constructionCountData = playerDataDto.constructionCountData;
      playerDataEntity.researchBonus = playerDataDto.researchBonus;
      playerDataEntity.lastSaveTime = playerDataDto.lastSaveTime;
      playerDataEntity.ranking = playerDataDto.ranking;
      playerDataEntity.lastClaimDailyChestTime = playerDataDto.lastClaimDailyChestTime;
      playerDataEntity.lastClaimDailyGemTime = playerDataDto.lastClaimDailyGemTime;
      playerDataEntity.equipedEquipment = playerDataDto.equipedEquipment;
      playerDataEntity.ownedEquipment = playerDataDto.ownedEquipment;

      return await this.playerDataRepository.save(playerDataEntity);
    } catch (error) {
      console.error('Error saving player data:', error.message);
      throw new BadRequestException('Invalid player data format');
    }
  }

  // Optional utility method to sanitize JSON strings
  sanitizeJsonString(decryptedData: string): string {
    // Remove any non-printable characters (e.g., control characters)
    const sanitizedData = decryptedData.replace(/[^ -~]+/g, '');

    // Optional: If necessary, trim any trailing/leading spaces or control characters
    return sanitizedData.trim();
  }

  async getPlayerData(userId: number): Promise<UserDto | null> {
    return await this.userRepository.findOne({
      where: { id: userId },
      relations: ['playerData'],
    });
  }

  async deleteAccount(userId: number): Promise<DefaultResponse> {
    try {
      return await this.userRepository.manager.transaction(async (entityManager: EntityManager) => {
        const user = await entityManager.findOne(UserEntity, {
          where: { id: userId },
        });

        if (!user) {
          throw new BadRequestException('User not found');
        }

        user.username = `${user.username}_deleted_${user.id}`;
        await entityManager.save(UserEntity, user);

        const saveId = await entityManager.findOne(PlayerDataEntity, {
          where: { userId },
        });

        await entityManager.softDelete(PlayerDataEntity, saveId.id);
        await entityManager.softDelete(UserEntity, userId);

        return {
          status: 200,
          message: "Delete success"
        };
      });
    } catch (error) {
      throw new BadRequestException('Delete fail');
    }
  }

  async disconnectAccount(userId: number, signupRequest: SignupRequest): Promise<AuthResponse> {
    try {
      const { username, password, display_name } = signupRequest;
      const existUser = await this.userRepository.findOne({
        where: {
          id: userId,
        },
      });

      if (existUser) {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);

        existUser.username = username;
        existUser.password = hash;
        existUser.display_name = display_name;
        existUser.is_guest = true;
        existUser.is_social = false;

        const user = await this.userRepository.save(existUser);
        delete user.password;
        return this.generateToken(user.id, user.username, user.role);
      } else {
        throw new UnauthorizedException(USER_NOT_FOUND)
      }
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  async getRanking(userId: number, take: number, skip: number): Promise<RankDto | null> {
    const data = await this.playerDataRepository.find({
      relations: ['user'],
      order: {
        ranking: 'DESC',
      },
      take: take,
      skip: skip,
    });

    const playerData = await this.playerDataRepository.findOne({
      where: {
        userId: userId,
      },
      relations: ['user'],
    })

    const higherRankCount = await this.playerDataRepository.count({
      where: { ranking: MoreThan(playerData.ranking) }
    });
  
    const playerRank = higherRankCount + 1;

    return {
      playerPlace: Number(playerRank),
      playerData: playerData,
      data: data,
    }
  }

  async updateRegion(userId: number, request: UpdateRequest): Promise<UserDto> {
    const { region, display_name } = request;
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
      },
    });

    if (!user) throw new UnauthorizedException(USER_NOT_FOUND)

    user.region = region ? region : user.region;
    user.display_name = display_name ? display_name : user.display_name;

    return await this.userRepository.save(user);
  }
}
