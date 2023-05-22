import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtGuard } from '../auth/guard/jwt.guard';
import { GetUser } from '../auth/decorator/user.decorator';
import { User } from '@prisma/client';

@Controller('user')
export class UserController {
  @UseGuards(JwtGuard)
  @Get('me')
  me(@GetUser() user: User) {
    return user;
  }
}
