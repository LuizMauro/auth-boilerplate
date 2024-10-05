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
          secure: false,
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        },
        defaults: {
          from: '"No Reply" <noreply@example.com>',
        },
      }),
    }),
  ],

  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
