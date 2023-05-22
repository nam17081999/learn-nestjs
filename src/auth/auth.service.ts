import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import * as argon from 'argon2';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(body: RegisterDto) {
    const { email, password, firstName, lastName } = body;
    const hashPassword = await argon.hash(password);
    try {
      const user = await this.prismaService.user.create({
        data: {
          email,
          hash: hashPassword,
          firstName,
          lastName,
        },
      });
      delete user.hash;
      return { user };
    } catch (error) {
      throw new ForbiddenException(error.message);
    }
  }

  async login(body: LoginDto) {
    const { email, password } = body;
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email,
        },
      });
      if (!user) {
        throw new ForbiddenException('Invalid credentials');
      }
      const isPasswordValid = await argon.verify(user.hash, password);
      if (!isPasswordValid) {
        throw new ForbiddenException('Invalid credentials');
      }
      delete user.hash;
      const jwt = await this.signJwtToken(user.id, user.email);
      return { user, jwt };
    } catch (error) {
      throw new ForbiddenException(error.message);
    }
  }

  signJwtToken(userId: number, email: string) {
    const payload = { userId, email };
    return this.jwtService.signAsync(payload, {
      expiresIn: '10m',
      secret: process.env.JWT_SECRET,
    });
  }
}
