import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { User } from '../user/user.entity';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<User> {
    const { name, email, password } = registerDto;
    const existingUser = await this.userService.findByEmail(email);

    if (existingUser) {
      throw new UnauthorizedException('User with this email already exists');
    }

    return this.userService.createUser(name, email, password);
  }

  async login(loginDto: LoginDto): Promise<{ accessToken: string }> {
    const { email, password } = loginDto;
    const user = await this.userService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload);

    return { accessToken };
  }

  async requestPasswordReset(email: string): Promise<void> {
    const resetToken = await this.userService.generateResetToken(email);
    await this.mailService.sendResetPasswordEmail(email, resetToken);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.userService.findByResetToken(token);
    if (!user) {
      throw new NotFoundException('Invalid or expired password reset token');
    }

    await this.userService.updatePassword(user.id, newPassword);
  }

  async requestPasswordResetOtp(email: string): Promise<void> {
    const otp = await this.userService.generateOtp(email);
    await this.mailService.sendResetPasswordOtp(email, otp);
  }

  async resetPasswordWithOtp(
    email: string,
    otp: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userService.validateOtp(email, otp);
    user.password = await bcrypt.hash(newPassword, 10);
    await this.userService.updateUser(user);
    await this.userService.clearOtp(user.id);
  }
}
