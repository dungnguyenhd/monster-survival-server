import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserEntity } from 'src/user/entities/user.entity';

export const User = createParamDecorator(
  (data, ctx: ExecutionContext): Promise<UserEntity> => {
    const req = ctx.switchToHttp().getRequest();
    return req.user;
  },
);
