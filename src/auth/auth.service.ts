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

    // Resetar tentativas falhas ao fazer login com sucesso
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

  private async handleFailedLoginAttempt(user: User) {
    const currentTime = new Date();
    const timeDifference = user.lastFailedLoginAttempt
      ? (currentTime.getTime() - user.lastFailedLoginAttempt.getTime()) / 1000
      : null;

    if (timeDifference && timeDifference > 300) {
      // Se passaram mais de 5 minutos desde a última tentativa falha, resetar contador
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
}
