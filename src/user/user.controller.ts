import { BadRequestException, Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Put, Req, Res, UseGuards } from '@nestjs/common';
import { CreateUserDto } from 'src/dto/create-user.dto';
import { UserService } from './user.service';
import * as bcrypt from 'bcrypt';
import { Request,Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { JwtService } from '@nestjs/jwt';
import { signJWT } from 'src/utils/jwt.utils';

@Controller('user')
export class UserController {
   
//   jwtService: any;
    constructor(private readonly userService: UserService,private jwtService: JwtService) {}
  
    @Get()
    gethello(){
      return this.userService.gethello();
    }
  
  
    @Get('/user')
    getUser(){
           return this.userService.findUserById(); 
    }

    @Post('register')
    async register(
        @Body('name') name: string,
        @Body('email') email: string,
        @Body('password') password: string
    ) {
        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await this.userService.create({
            name,
            email,
            password: hashedPassword
        });

        delete user.password;

        return user;
    }

    
  
    @Post('login')
    async login(
        @Body('id') id: number,
        @Body('password') password: string,
        @Res({passthrough: true}) response: Response,
        @Req() request: Request
    ) {
        const user = await this.userService.findOne({id});

        if (!user) {
            throw new BadRequestException('invalid credentials');
        }

        if (!await bcrypt.compare(password, user.password)) {
            throw new BadRequestException('invalid credentials');
        }

        // const jwt = this.jwtService.signAsync({id: user.id});
        const payload = { id: user.id };
        const jwt = this.jwtService.sign(payload);

       const decoded =  this.jwtService.verify(jwt);

      const updateToken= {
        refresh_token: jwt,
        refresh_token_iat: decoded.iat,
       }

       await this.userService.setCurrentIATRefreshToken(updateToken,id)

    //   await this.userService.setCurrentRefreshToken(jwt,id)
      
        return {
            RefreshToken: jwt,
            message: 'success'
        };
    }

    
  
  @Put(':id')
  updateUserbyId(@Param('id',ParseIntPipe) id:number,@Body() update:CreateUserDto){
    return this.userService.updateUser(id,update);
  }
  @Delete(':id')
 DelUserbyId(@Param('id',ParseIntPipe) id:number){
    return this.userService.deletUser(id);
  }

  @Post('logout')
    async logout(@Res({passthrough: true}) response: Response) {
        response.clearCookie('jwt');

        return {
            message: 'success'
        }
    }

    @Post('token/api')
      async createSessionHandler(@Body('email') email: string,
      @Body('password') password: string,
      @Res({passthrough: true}) response: Response,
      @Req() request: Request
      ) {
      
      
        const user = await this.userService.getUser({email});
      
        if (!user) {
          throw new BadRequestException('invalid credentials');
      }

      if (!await bcrypt.compare(password, user.password)) {
          throw new BadRequestException('invalid credentials');
      }
    
      
        // create access token
        const accessToken = signJWT(
          { email: user.email,password: user.password},
          "15s"
        );
      
        const refreshToken =  signJWT({ email: user.email,password: user.password }, "1y");
      
       
       response.cookie("accessToken", accessToken, {
          maxAge: 300000, 
          httpOnly: true,
        });
      
       response.cookie("refreshToken", refreshToken, {
          maxAge: 3.154e10, 
          httpOnly: true,
        });
      
        // send user back
        return {
            accessToken,
            refreshToken
        };
      }

      @Get('/token')
      async verifytheToken(@Req() request: Request): Promise<any> {
        const jwt = request.headers.authorization.replace('Bearer ', '');
        const json: any =this.jwtService.decode(jwt, { json: true }) as { id: number };
        const data = await this.userService.findOneById(json.id);
        console.log(json.iat)
        console.log(data);

          
      }
      
      // get the session session
      
      // log out handler
    //   export function getSessionHandler(req: Request, res: Response) {
    //     // @ts-ignore
    //     return res.send(req.user);
    //   }
      
    //   export function deleteSessionHandler(req: Request, res: Response) {
    //     res.cookie("accessToken", "", {
    //       maxAge: 0,
    //       httpOnly: true,
    //     });
      
    //     res.cookie("refreshToken", "", {
    //       maxAge: 0,
    //       httpOnly: true,
    //     });
      
    //     // @ts-ignore
    //     const session = invalidateSession(req.user.sessionId);
      
    //     return res.send(session);
    //   }
}
