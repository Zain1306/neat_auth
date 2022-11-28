import {Module} from '@nestjs/common';
import {TypeOrmModule} from '@nestjs/typeorm';
import {AppController} from './app.controller';
import {AppService} from './app.service';
import {User} from "./user.entity";
import {JwtModule} from "@nestjs/jwt";
import { ConfigModule } from '@nestjs/config';
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
            signOptions: {expiresIn: '1d'}
        }),
    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {
}
