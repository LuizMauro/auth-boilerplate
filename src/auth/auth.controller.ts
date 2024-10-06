import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import { CustomThrottlerGuard } from './custom-throttler.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuthenticatedRequest } from 'src/types/express-request.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @UseGuards(CustomThrottlerGuard)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body('email') email: string) {
    await this.authService.requestPasswordReset(email);
    return { message: 'Password reset email sent' };
  }

  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    await this.authService.resetPassword(token, newPassword);
    return { message: 'Password has been reset' };
  }

  @Post('request-password-reset-otp')
  async requestPasswordResetOtp(@Body('email') email: string) {
    await this.authService.requestPasswordResetOtp(email);
    return { message: 'OTP sent to your email' };
  }

  @Post('verify-otp')
  async verifyOtp(@Body('email') email: string, @Body('otp') otp: string) {
    const result = await this.authService.verifyOtp(email, otp);
    return { result };
  }

  @Post('reset-password-with-otp')
  async resetPasswordWithOtp(
    @Body('resetToken') resetToken: string,
    @Body('newPassword') newPassword: string,
  ) {
    await this.authService.resetPasswordWithToken(resetToken, newPassword);
    return { message: 'Password has been reset' };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: AuthenticatedRequest) {
    const token = req.headers.authorization.split(' ')[1];
    await this.authService.logout(token);
    return { message: 'Logout realizado com sucesso.' };
  }
}
