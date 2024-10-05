import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendResetPasswordEmail(email: string, resetToken: string) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    try {
      await this.mailerService.sendMail({
        from: '"Auth Boilerplate" <no-reply@example.com>',
        to: email,
        subject: 'Password Reset Request',
        text: `You requested a password reset. Click here to reset your password: ${resetUrl}`,
        html: `<p>You requested a password reset. Click here to reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`,
      });
    } catch (error) {
      console.error('Failed to send reset password email:', error);
      throw new Error(
        'There was an error sending the reset email. Please try again later.',
      );
    }
  }

  async sendResetPasswordOtp(email: string, otp: string) {
    try {
      await this.mailerService.sendMail({
        from: '"Auth Boilerplate" <no-reply@example.com>',
        to: email,
        subject: 'Your Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}`,
        html: `<p>Your OTP for password reset is: <strong>${otp}</strong></p>`,
      });
    } catch (error) {
      console.error('Failed to send reset password email:', error);
      throw new Error(
        'There was an error sending the reset email. Please try again later.',
      );
    }
  }
}
