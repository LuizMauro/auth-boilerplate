import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Exclude } from 'class-transformer';

import { Session } from 'src/session/session.entity';

export type UserRole = 'user' | 'admin';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Exclude()
  @Column({ nullable: true })
  password: string;

  @Exclude()
  @Column({ nullable: true })
  provider: string;

  @Exclude()
  @Column({ nullable: true })
  providerId: string;

  @Exclude()
  @Column({ nullable: true })
  resetToken: string;

  @Exclude()
  @Column({ nullable: true, type: 'timestamp' })
  resetTokenExpiry: Date;

  @Exclude()
  @Column({ nullable: true })
  otp: string;

  @Exclude()
  @Column({ nullable: true, type: 'timestamp' })
  otpExpiry: Date;

  @Exclude()
  @Column({ default: 'user' })
  role: UserRole;

  @Exclude()
  @Column({ default: 0 })
  failedLoginAttempts: number;

  @Exclude()
  @Column({ type: 'timestamp', nullable: true })
  lastFailedLoginAttempt: Date;

  @Exclude()
  @OneToMany(() => Session, (session) => session.user)
  sessions: Session[];

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
