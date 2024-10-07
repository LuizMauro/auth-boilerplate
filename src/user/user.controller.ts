import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('user')
@ApiBearerAuth('access-token') // Deve ser o mesmo nome definido no DocumentBuilder
@UseGuards(JwtAuthGuard, RolesGuard)
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
