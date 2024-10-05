import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MoreThan, Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | undefined> {
    return this.userRepository.findOne({ where: { email } });
  }

  async createUser(
    name: string,
    email: string,
    password: string,
  ): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = this.userRepository.create({
      name,
      email,
      password: hashedPassword,
    });
    return this.userRepository.save(user);
  }

  async generateResetToken(email: string): Promise<string> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const resetToken = randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // Expira em 10 minutos

    user.resetToken = resetToken;
    user.resetTokenExpiry = expiry;

    await this.userRepository.save(user);
    return resetToken;
  }

  async findByResetToken(token: string): Promise<User | undefined> {
    return this.userRepository.findOne({
      where: {
        resetToken: token,
        resetTokenExpiry: MoreThan(new Date()),
      },
    });
  }

  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
      },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;

    await this.userRepository.save(user);
  }
}
