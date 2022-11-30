import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from 'src/dto/create-user.dto';
import { UpdateUserDto } from 'src/dto/update-user.dto';
import { User } from 'src/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UserService {
  userService: any;
  private jwtService: JwtService
    
  constructor(@InjectRepository(User)
  private readonly userRepositary: Repository<User>){

  }
   
  gethello(){
    return 'hello word';
  }
  
  findUserById(){
   return  this.userRepositary.find();
  }
  
  createUser(cretuse :CreateUserDto)
  {
    return this.userRepositary.save(cretuse);
  }

    updateUser(id:number,updateuser:CreateUserDto)
    {
      return this.userRepositary.update({id},{...updateuser});
    }

    deletUser(id:number){
      return this.userRepositary.delete({id});
    }

    patchUser(id:number,updates:UpdateUserDto){
      return this.userRepositary.update({id},{});
    }

    async create(data: any): Promise<User> {
        return this.userRepositary.save(data);
    }

    async findOne(condition: any): Promise<User> {
      return this.userRepositary.findOne(condition);
  }

  // async setCurrentRefreshToken(refreshToken: string, id: number) {
  //     const currentHashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      
  //     return await this.userRepositary.update(id, {
  //       refresh_token: currentHashedRefreshToken
  //     });
  //   }

    async setCurrentIATRefreshToken(refreshToken: UpdateUserDto, id: number) {
      
     
      //  return await this.userRepositary.update(id, {
      //     refresh_token_iat: refreshToken.refresh_token_iat,
      //     refresh_token: refreshToken.refresh_token
      // });
      return await this.userRepositary.update(id,refreshToken);
    }

    async validateUser(name: string, pass: string): Promise<any> {
      const user = await this.userService.findOne(name);
      if (user && user.password === pass) {
        const { password, ...result } = user;
        return result;
      }
      return null;
    }


     getUser(condition: any): Promise<User> {
      return this.userRepositary.findOne(condition);
  }
  
  async findOneById(condition: any): Promise<User> {
    return this.userRepositary.findOne(condition);
}
}
