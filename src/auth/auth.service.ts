import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2"

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {

    }
    async signup(dto: AuthDto) {
        // generate the password
        const hash = await argon.hash(dto.password);
        // save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash
                }
            })

            delete user.hash
            // return the saved user
            return user;
        
        } catch(error) {
            if(error.code == "P2002"){
                throw new ForbiddenException("Credentials Taken")
            }
            // if (error instanceof PrismaClientKnownRequestError){
        }
        // }
    }
    async singin(dto: AuthDto) {
        // Find the user by email
        const user = await this.prisma.user.findUnique({
            where: {email: dto.email}       
        })

      
      
        //if user does not exists throw exception
        if(!user){
            throw new ForbiddenException("Credendials incorrect");            
        }
        
        // compare passwords
        const pwMatches = await argon.verify(user.hash, dto.password);
        console.log(pwMatches);
        
        if(!pwMatches)
            throw new ForbiddenException("Credendials incorrect");            

        delete user.hash
        return user;        
    }
}
