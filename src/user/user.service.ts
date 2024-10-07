import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  PlayerDataDto,
  SigninRequest,
  SignupRequest,
} from './dto/user_request.dto';
import { DataSource, Like, Repository } from 'typeorm';
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
  ) { }

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
    const { username, password, display_name } = request;
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
    updateUser.password = password;
    updateUser.display_name = display_name;
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

      // Map fields from DTO to Entity
      playerDataEntity.userId = userId;
      playerDataEntity.hallLevel = playerDataDto.hallLevel;
      playerDataEntity.currentDay = playerDataDto.currentDay;
      playerDataEntity.listPlacementData = playerDataDto.listPlacementData;
      playerDataEntity.inventoryData = playerDataDto.inventoryData;
      playerDataEntity.resources = playerDataDto.resources;
      playerDataEntity.lastSaveTime = playerDataDto.lastSaveTime;

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
      const saveId = await this.playerDataRepository.findOne({
        where: { userId },
      });

      await this.playerDataRepository.softDelete(saveId.id);
      await this.userRepository.softDelete(userId);
      return {
        status: 200,
        message: "Delete success"
      }
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
      order: {
        ranking: 'DESC',
      },
      take: take,
      skip: skip,
    })

    const playerRank = await this.playerDataRepository
      .createQueryBuilder('player_data')
      .select(
        `RANK() OVER (ORDER BY player_data.ranking DESC)`,
        'player_rank',
      )
      .where('player_data.userId = :userId', { userId })
      .getRawOne();

    return {
      playerPlace: playerRank,
      data: data,
    }
  }
}
