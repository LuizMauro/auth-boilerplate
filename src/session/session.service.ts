import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Session } from './session.entity';
import { User } from '../user/user.entity';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(Session)
    private readonly sessionRepository: Repository<Session>,
  ) {}

  async createSession(
    user: User,
    token: string,
    jti: string,
  ): Promise<Session> {
    const session = this.sessionRepository.create({ user, id: jti, token });
    return this.sessionRepository.save(session);
  }

  async findSessionByTokenId(jti: string): Promise<Session> {
    return this.sessionRepository.findOne({ where: { id: jti } });
  }

  async findByToken(token: string): Promise<Session> {
    return this.sessionRepository.findOne({ where: { token } });
  }

  async deleteSession(token: string): Promise<void> {
    const session = await this.findByToken(token);
    if (!session) {
      throw new NotFoundException('Sessão não encontrada');
    }
    await this.sessionRepository.remove(session);
  }
}
