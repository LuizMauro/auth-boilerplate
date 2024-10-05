import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { SessionService } from 'src/session/session.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly sessionService: SessionService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'secretKey',
    });
  }

  async validate(payload: any) {
    console.log('JWT Payload:', payload); // Adicionando log para verificar o payload

    if (
      !payload ||
      !payload.sub ||
      !payload.email ||
      !payload.role ||
      !payload.jti
    ) {
      throw new UnauthorizedException('Invalid token payload');
    }

    const session = await this.sessionService.findSessionByTokenId(payload.jti);

    if (!session) {
      throw new UnauthorizedException(
        'Token inválido ou sessão não encontrada',
      );
    }

    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
      jti: payload.jti,
    };
  }
}
