import { Controller, Get, Post, Body } from '@nestjs/common';
import { UserService } from './user.service';
import {
  SaveRequestDto,
  SigninRequest,
  SignupRequest,
} from './dto/user_request.dto';
import { User } from 'src/common/decorators/user.decorator';
import { AuthResponse, UserDto } from './dto/user_response.dto';
import { Auth } from 'src/common/decorators/auth.decorator';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('user')
@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('signup')
  async signup(@Body() signupRequest: SignupRequest): Promise<AuthResponse> {
    return await this.userService.signup(signupRequest);
  }

  @Post('signin')
  async signin(@Body() signinRequest: SigninRequest): Promise<AuthResponse> {
    return await this.userService.signin(signinRequest);
  }

  @Post('save')
  @Auth()
  async savePlayerData(
    @User() user: UserDto,
    @Body() saveRequestDto: SaveRequestDto,
  ) {
    return await this.userService.savePlayerData(
      user.id,
      saveRequestDto.encryptedData,
      saveRequestDto.nonce,
    );
  }

  @Get()
  @Auth()
  async getPlayerData(@User() user: UserDto) {
    return await this.userService.getPlayerData(user.id);
  }
}
