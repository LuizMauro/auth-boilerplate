import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ description: 'O nome do usuário', example: 'João Silva' })
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    description: 'O email do usuário',
    example: 'usuario@exemplo.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'A senha do usuário',
    example: 'senhaSegura123',
    minLength: 6,
  })
  @MinLength(6)
  password: string;
}
