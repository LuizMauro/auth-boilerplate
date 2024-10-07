import { ThrottlerGuard } from '@nestjs/throttler';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected async throwThrottlingException(): Promise<void> {
    throw new HttpException(
      'Muitas requisições. Por favor, tente novamente mais tarde.',
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }
}
