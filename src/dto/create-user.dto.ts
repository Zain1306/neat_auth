import { IsNotEmpty } from "class-validator";
import { string } from "joi";


export class CreateUserDto {
@IsNotEmpty()
id: number;

@IsNotEmpty()
email: string;


}
