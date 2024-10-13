import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { ApiBearerAuth } from '@nestjs/swagger';
import { AuthenticatedRequest } from 'src/types/express-request.interface';

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

  @Get('profile')
  async getProfile(@Req() req: AuthenticatedRequest) {
    const user = this.userService.findById(req.user.sub);

    return user;
  }

  @Roles('user', 'admin')
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }
}
