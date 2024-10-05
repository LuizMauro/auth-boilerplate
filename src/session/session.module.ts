import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SessionService } from './session.service';
import { Session } from './session.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Session])], // Importa a entidade Session
  providers: [SessionService], // Declara o SessionService como um provedor
  exports: [SessionService], // Exporta o SessionService para ser usado em outros módulos
})
export class SessionModule {}
