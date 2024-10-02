import { PassportStrategy } from '@nestjs/passport';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../entities/user.entity';
import { JwtPayload } from '../dto/user_request.dto';
import { UserDto } from '../dto/user_response.dto';
import { USER_NOT_FOUND } from 'src/common/constants/error.constant';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    public readonly configService: ConfigService,
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // ignoreExpiration: false,
      secretOrKey: configService.get('SECRETKEY'),
    });
  }

  async validate(payload: JwtPayload): Promise<UserDto> {
    const { id } = payload;
    const user: UserEntity | undefined = await this.userRepository.findOne({
      where: { id: id },
      relations: ['playerData'],
    });
    if (!user) {
      throw new NotFoundException(USER_NOT_FOUND);
    }

    const result: UserDto = {
      id: user.id,
      username: user.username,
      role: user.role,
      display_name: user.display_name,
      playerData: user.playerData,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
    return result;
  }
}
