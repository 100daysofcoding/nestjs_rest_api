import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from './mailer/mailer.module';

@Module({
  imports: [ConfigModule.forRoot({isGlobal : true}) , AuthModule, PrismaModule, MailerModule],
})
export class AppModule {}
