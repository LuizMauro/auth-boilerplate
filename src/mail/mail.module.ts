import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { MailService } from './mail.service';

@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: async () => ({
        transport: {
          host: process.env.EMAIL_HOST,
          port: Number(process.env.EMAIL_PORT),
          secure: true,
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        },
        defaults: {
          from: '"No Reply" <no-reply@resend.dev>',
        },
      }),
    }),
  ],

  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
