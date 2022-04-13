import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2"
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {

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
            this.signToken(user.id, user.email)

            return this.signToken(user.id, user.email)
        } catch (error) {
            if (error.code == "P2002") {
                throw new ForbiddenException("Credentials Taken")
            }
        }

    }
    async singin(dto: AuthDto) {
        // Find the user by email
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email }
        })



        //if user does not exists throw exception
        if (!user) {
            throw new ForbiddenException("Credendials incorrect");
        }

        // compare passwords
        const pwMatches = await argon.verify(user.hash, dto.password);
        console.log(pwMatches);

        if (!pwMatches)
            throw new ForbiddenException("Credendials incorrect");

        return this.signToken(user.id, user.email)

    }


    async signToken(userId: number, email: string): Promise<{access_token:string}> {
        const payload = {
            sub: userId,
            email
        }
        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: this.config.get("JWT_SECRET")
        })

        return {access_token:token};
    }
}
