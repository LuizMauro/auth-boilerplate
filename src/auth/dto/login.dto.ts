import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    description: 'O email do usuário',
    example: 'usuario@exemplo.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'A senha do usuário', example: 'senhaSegura123' })
  @IsNotEmpty()
  password: string;
}
