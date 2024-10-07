import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

import { CustomThrottlerGuard } from './custom-throttler.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuthenticatedRequest } from 'src/types/express-request.interface';

@ApiTags('auth')
@ApiBearerAuth('access-token') // Deve ser o mesmo nome definido no DocumentBuilder
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Registrar um novo usuário' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'Usuário registrado com sucesso' })
  @ApiResponse({ status: 400, description: 'Dados inválidos' })
  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @ApiOperation({ summary: 'Login do usuário' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Login realizado com sucesso' })
  @ApiResponse({ status: 401, description: 'Credenciais inválidas' })
  @UseGuards(CustomThrottlerGuard)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @ApiOperation({ summary: 'Solicitar redefinição de senha via email' })
  @ApiBody({
    schema: { type: 'object', properties: { email: { type: 'string' } } },
  })
  @ApiResponse({
    status: 200,
    description: 'Email de redefinição de senha enviado',
  })
  @ApiResponse({ status: 404, description: 'Usuário não encontrado' })
  @Post('request-password-reset')
  async requestPasswordReset(@Body('email') email: string) {
    await this.authService.requestPasswordReset(email);
    return { message: 'Password reset email sent' };
  }

  @ApiOperation({ summary: 'Redefinir senha com token' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string' },
        newPassword: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Senha redefinida com sucesso' })
  @ApiResponse({ status: 400, description: 'Token inválido ou expirado' })
  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    await this.authService.resetPassword(token, newPassword);
    return { message: 'Password has been reset' };
  }

  @ApiOperation({ summary: 'Solicitar redefinição de senha via OTP' })
  @ApiBody({
    schema: { type: 'object', properties: { email: { type: 'string' } } },
  })
  @ApiResponse({ status: 200, description: 'OTP enviado para o email' })
  @ApiResponse({ status: 404, description: 'Usuário não encontrado' })
  @Post('request-password-reset-otp')
  async requestPasswordResetOtp(@Body('email') email: string) {
    await this.authService.requestPasswordResetOtp(email);
    return { message: 'OTP sent to your email' };
  }

  @ApiOperation({ summary: 'Validar OTP' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: { email: { type: 'string' }, otp: { type: 'string' } },
    },
  })
  @ApiResponse({ status: 200, description: 'OTP validado com sucesso' })
  @ApiResponse({ status: 400, description: 'OTP inválido ou expirado' })
  @Post('verify-otp')
  async verifyOtp(@Body('email') email: string, @Body('otp') otp: string) {
    const result = await this.authService.verifyOtp(email, otp);
    return { result };
  }

  @ApiOperation({ summary: 'Redefinir senha com OTP' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        resetToken: { type: 'string' },
        newPassword: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Senha redefinida com sucesso' })
  @ApiResponse({
    status: 400,
    description: 'Token de redefinição inválido ou expirado',
  })
  @Post('reset-password-with-otp')
  async resetPasswordWithOtp(
    @Body('resetToken') resetToken: string,
    @Body('newPassword') newPassword: string,
  ) {
    await this.authService.resetPasswordWithToken(resetToken, newPassword);
    return { message: 'Password has been reset' };
  }

  @ApiOperation({ summary: 'Logout do usuário' })
  @ApiResponse({ status: 200, description: 'Logout realizado com sucesso' })
  @ApiResponse({ status: 401, description: 'Usuário não autorizado' })
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req: AuthenticatedRequest) {
    const token = req.headers.authorization.split(' ')[1];
    await this.authService.logout(token);
    return { message: 'Logout realizado com sucesso.' };
  }
}
