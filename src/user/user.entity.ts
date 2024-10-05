import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password: string;

  @Column({ nullable: true })
  provider: string;

  @Column({ nullable: true })
  providerId: string;

  @Column({ nullable: true })
  resetToken: string;

  @Column({ nullable: true, type: 'timestamp' })
  resetTokenExpiry: Date;

  @Column({ nullable: true })
  otp: string;

  @Column({ nullable: true, type: 'timestamp' })
  otpExpiry: Date;
}
