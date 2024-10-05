import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { MailModule } from './mail/mail.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 5432,
      username: process.env.DB_USERNAME || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
      database: process.env.DB_NAME || 'auth_db',
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true, // Não use em produção
    }),
    ThrottlerModule.forRoot([
      {
        limit: Number(process.env.RATE_LIMITING_LIMIT), // Número máximo de requisições permitidas
        ttl: Number(process.env.RATE_LIMITING_TTL), // Tempo de vida (em segundos) da janela de limite de requisições
      },
    ]),
    UserModule,
    AuthModule,
    MailModule,
  ],
  providers: [],
})
export class AppModule {}
