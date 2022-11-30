import { IsNotEmpty, Length } from "class-validator";

export class CreateUserDto{
    @IsNotEmpty({message:'The user name'})
    @Length(3,255)
    name:string;
    @IsNotEmpty()
    @Length(3)
    description:string;
}