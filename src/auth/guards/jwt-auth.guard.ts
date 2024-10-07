import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest(err, user, info) {
    if (err || !user) {
      if (info && info.name === 'TokenExpiredError') {
        throw new UnauthorizedException(
          'Token expirado. Por favor, faça login novamente.',
        );
      } else if (info && info.name === 'JsonWebTokenError') {
        throw new UnauthorizedException(
          'Token inválido. Por favor, forneça um token válido.',
        );
      } else {
        throw new UnauthorizedException(
          'Não autorizado. O token é obrigatório para acessar esse recurso.',
        );
      }
    }
    return user;
  }
}
