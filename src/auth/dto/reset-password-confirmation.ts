
import {IsNotEmpty, IsEmail} from 'class-validator'
export class ResetPasswordConfirmationDto {
    @IsEmail()
    readonly email : string
    @IsNotEmpty()
    readonly password : string
    @IsNotEmpty()
    readonly code : string
}