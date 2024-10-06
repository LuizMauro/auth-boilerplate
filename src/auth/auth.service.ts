import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { User } from '../user/user.entity';
import { MailService } from 'src/mail/mail.service';
import { SessionService } from 'src/session/session.service';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
    private readonly sessionService: SessionService,
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
      throw new UnauthorizedException(
        'Credenciais inválidas. Verifique seu email e senha.',
      );
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await this.handleFailedLoginAttempt(user);
      throw new UnauthorizedException(
        'Credenciais inválidas. Verifique seu email e senha.',
      );
    }

    user.failedLoginAttempts = 0;
    await this.userService.updateUser(user);

    const jti = uuidv4();
    const payload = { sub: user.id, email: user.email, role: user.role, jti };
    const accessToken = this.jwtService.sign(payload);

    await this.sessionService.createSession(user, accessToken, jti);

    return { accessToken };
  }

  async logout(token: string): Promise<void> {
    await this.sessionService.deleteSession(token);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const resetToken = await this.generateResetToken(email);
    await this.mailService.sendResetPasswordEmail(email, resetToken);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.userService.findByResetToken(token);
    if (!user) {
      throw new NotFoundException('Invalid or expired password reset token');
    }

    if (user.resetTokenExpiry && user.resetTokenExpiry < new Date()) {
      throw new UnauthorizedException('Token de redefinição expirado.');
    }

    await this.userService.updatePassword(user.id, newPassword);
    this.mailService.notificationResetPassword(user.email);
  }

  async requestPasswordResetOtp(email: string): Promise<void> {
    const otp = await this.generateOtp(email);
    await this.mailService.sendResetPasswordOtp(email, otp);
  }

  async resetPasswordWithToken(
    resetToken: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userService.findByResetToken(resetToken);
    if (!user) {
      throw new NotFoundException('Token de redefinição inválido ou expirado.');
    }

    if (user.resetTokenExpiry && user.resetTokenExpiry < new Date()) {
      throw new UnauthorizedException('Token de redefinição expirado.');
    }

    await this.userService.updatePassword(user.id, newPassword);
    this.mailService.notificationResetPassword(user.email);
  }

  private async handleFailedLoginAttempt(user: User) {
    const currentTime = new Date();
    const timeDifference = user.lastFailedLoginAttempt
      ? (currentTime.getTime() - user.lastFailedLoginAttempt.getTime()) / 1000
      : null;

    if (timeDifference && timeDifference > 300) {
      user.failedLoginAttempts = 1;
    } else {
      user.failedLoginAttempts += 1;
    }

    user.lastFailedLoginAttempt = currentTime;

    if (user.failedLoginAttempts >= Number(process.env.FAILED_LOGIN_ATTEMPTS)) {
      await this.mailService.sendSecurityAlertEmail(user.email);
    }

    await this.userService.updateUser(user);
  }

  async verifyOtp(email: string, otp: string): Promise<{ resetToken: string }> {
    const user = await this.userService.findByEmail(email);
    if (!user || user.otp !== otp) {
      throw new UnauthorizedException(
        'OTP inválido ou usuário não encontrado.',
      );
    }

    if (user.otpExpiry && user.otpExpiry < new Date()) {
      throw new UnauthorizedException('OTP expirado.');
    }

    const resetToken = await this.generateResetToken(user.email);

    return { resetToken };
  }

  async generateResetToken(email: string): Promise<string> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const resetToken = randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    user.resetToken = resetToken;
    user.resetTokenExpiry = expiry;
    user.otp = null;
    user.otpExpiry = null;

    await this.userService.updateUser(user);

    return resetToken;
  }

  async generateOtp(email: string): Promise<string> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const otp = randomBytes(3).toString('hex');
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpiry = expiry;

    await this.userService.updateUser(user);
    return otp;
  }
}
