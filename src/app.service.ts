import {Injectable} from '@nestjs/common';
import {InjectRepository} from "@nestjs/typeorm";
import {User} from "./user.entity";
import {Repository} from "typeorm";
import * as bcrypt from 'bcrypt';

@Injectable()
export class AppService {
    constructor(
        @InjectRepository(User) private readonly userRepository: Repository<User>
    ) {
    }

    async create(data: any): Promise<User> {
        return this.userRepository.save(data);
    }

    async findOne(condition: any): Promise<User> {
        return this.userRepository.findOne(condition);
    }

    async setCurrentRefreshToken(refreshToken: string, id: number) {
        const currentHashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        
        return await this.userRepository.update(id, {
          refresh_token: currentHashedRefreshToken
        });
      }

      async setCurrentIATRefreshToken(refreshToken: any, id: number) {
        
        return await this.userRepository.update(id, {
            refresh_token_iat: refreshToken
        });
      }
   
}
