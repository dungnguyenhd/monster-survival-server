import { Controller, Get, Post, Body, Patch, Query, Delete } from '@nestjs/common';
import { UserService } from './user.service';
import {
  SaveRequestDto,
  SigninRequest,
  SignupRequest,
} from './dto/user_request.dto';
import { User } from 'src/common/decorators/user.decorator';
import { AuthResponse, DefaultResponse, UserDto } from './dto/user_response.dto';
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

  @Post("connect-account")
  @Auth()
  async connectAccount(@User() user: UserDto, @Body() signupRequest: SignupRequest): Promise<UserDto> {
    return await this.userService.connectAccount(user.id, signupRequest);
  }

  @Post("disconnect-account")
  @Auth()
  async disconnecetAccount(@User() user: UserDto, @Body() signupRequest: SignupRequest): Promise<AuthResponse> {
    return await this.userService.disconnectAccount(user.id, signupRequest);
  }

  @Delete("delete-account")
  @Auth()
  async deleteAccount(@User() user: UserDto): Promise<DefaultResponse> {
    return await this.userService.deleteAccount(user.id);
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

  @Get('ranking')
  @Auth()
  async getRanking(@User() user: UserDto, @Query('take') take: number, @Query('skip') skip: number) {
    return await this.userService.getRanking(user.id, take, skip);
  }
}
