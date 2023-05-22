import { ForbiddenException, Injectable } from "@nestjs/common";
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import * as process from 'process';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private prismaService: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    });
  }
  async validate(payload: { userId: number; email: string }) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          id: payload.userId,
        },
      });
      delete user.hash;
      return user;
    } catch (error) {
      throw new ForbiddenException(error.message);
    }
  }
}
