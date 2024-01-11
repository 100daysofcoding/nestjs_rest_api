import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt'
import * as speakeasy from 'speakeasy'
import { SignupDto } from './dto/signupDto';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailerService } from 'src/mailer/mailer.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/reset-password-confirmation';

@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService : PrismaService,
        private readonly mailerService : MailerService,
        private readonly jwtService: JwtService,
        private readonly configService : ConfigService
        ){}
    async signup(signupDto: SignupDto) {
        const {email, password , username} = signupDto ;
        // ** verifier si l'utilisateur est déjà inscrit
        let user= await this.prismaService.user.findUnique({where : {email}});
        if (user) throw new ConflictException(" User already exists");
        // ** Hasher le mot de passe
        const hash = await bcrypt.hash(password,10)
        // ** Enregistrer l'utilisateur dans la base de données
         await this.prismaService.user.create({
            data:{email,username,password:hash}
        })
        // ** Envoyer un email de confirmation
         await this.mailerService.sendSignupConfirmation(email)
        // ** Retourner une reponse de succès
        return { data : 'User succesfully created'} 
    }

    async signin(signinDto: SigninDto) {
        const {email, password} = signinDto
        // ** verifier si l'utilisateur est déjà inscrit 
        const user = await this.prismaService.user.findUnique({where: {email}})
        if(!user) throw new  NotFoundException("User not Found")
        // ** Comparer le mot de passe
        const match=await bcrypt.compare(password, user.password)
        if(!match) throw new UnauthorizedException("Password does not match")
        // ** Retourner un token jwt
        const playload = {
            sub : user.userId,
            email:user.email
        }
        const token = this.jwtService.sign(playload,{
            expiresIn:'2h',
            secret:this.configService.get('SECRET_KEY')
        })
        const data = {
            "token": token,
             "user" : {
                username: user.username,
                email: user.email
             }
        }
        return data
    }

    async resetPasswordDemand(resetPasswordDemandDto: ResetPasswordDemandDto) {
        const {email} = resetPasswordDemandDto
        // ** verifier si l'utilisateur est déjà inscrit 
        const user = await this.prismaService.user.findUnique({where: {email}})
        if(!user) throw new  NotFoundException("User not Found")
        const code = speakeasy.totp({
            secret : this.configService.get('OTP_CODE'),
            digits : 5,
            step : 60*15,
            encoding : "base32"
        })
        const url = "http://localhost:3000/auth/reset-password-confirmation";
        await this.mailerService.sendResetPassword(email,url,code)
        return {data : "Reset Password mail has been sent"}
    }

    async resetPasswordConfirmation(resetPasswordConfirmationDto: ResetPasswordConfirmationDto) {
        const {email,password,code} = resetPasswordConfirmationDto
        // ** verifier si l'utilisateur est déjà inscrit 
        const user = await this.prismaService.user.findUnique({where: {email}})
        if(!user) throw new  NotFoundException("User not Found")
        const match = speakeasy.totp.verify({
          secret: this.configService.get('OTP_CODE'),
          token: code,
          digits: 5,
          step: 60*15,
          encoding: 'base32'
        })
        if(!match) throw new UnauthorizedException("Invalid/Expired token")
        const hash = await bcrypt.hash(password,10)
        await this.prismaService.user.update({where: {email}, data: {password: hash}})
        return {data : "Password Updated"}
    }
}
 