import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from './user/user.module';
import Joi from 'joi';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'zain13',
      database: 'yt_nest_auth',
      entities: [User],
      synchronize: true,
    }),

    // ConfigModule.forRoot({
    //     validationSchema: Joi.object({
    //       ACCESS_TOKEN_SECRET: Joi.string().required(),
    //       ACCESS_TOKEN_EXPIRATION: Joi.string().required(),
    //       REFRESH_TOKEN_SECRET: Joi.string().required(),
    //       REFRESH_TOKEN_EXPIRATION: Joi.string().required(),
    //       // ...
    //     })
    //   }),

    TypeOrmModule.forFeature([User]),
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '1d' },
    }),
    UserModule,
  ],
})
export class AppModule {}
