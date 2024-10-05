import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('user')
@UseGuards(JwtAuthGuard, RolesGuard) // O JwtAuthGuard vem antes do RolesGuard
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Roles('admin')
  @Get()
  async findAll() {
    return this.userService.findAll();
  }

  @Roles('user', 'admin')
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }
}
