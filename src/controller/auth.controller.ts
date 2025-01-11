import express from "express";

import {IsEmail, IsString, IsStrongPassword, IsUrl, validateOrReject} from "class-validator";
import {Expose, plainToInstance} from "class-transformer";
import {EmailService} from "../services/email.service.js";
import {TokenService} from "../services/token.service.js";
import {Token} from "../entitites/token.entity.js";
import {UserService} from "../services/user.service.js";
import {User} from "../entitites/user.entity.js";
import {generateToken} from "../utils/jwt.utils.js";
import {appConfig} from "../config/app.config.js";
import {comparePassword} from "../utils/password.utils.js";

export class RegisterDto {
    @IsUrl({protocols: ['https']})
    @Expose()
    returnUrl: string;

    @IsEmail()
    @Expose()
    email: string;

    @IsStrongPassword({
        minSymbols: 1,
        minNumbers: 1,
        minUppercase: 1,
        minLowercase: 1,
        minLength: 8,
    })
    @Expose()
    password: string;
}

export class ResendRegisterMailDto {
    @IsUrl({protocols: ['https']})
    @Expose()
    returnUrl: string;

    @IsEmail()
    @Expose()
    email: string;
}

export class LoginDto {
    @IsEmail()
    @Expose()
    email: string;

    @IsString()
    @Expose()
    password: string;
}

export class AuthController {
    static async register(req: express.Request, res: express.Response): Promise<any> {
        const registerDto: RegisterDto = plainToInstance(RegisterDto, req.body, {excludeExtraneousValues: true});

        try {
            await validateOrReject(registerDto)
        } catch (e) {
            return res.status(400).send(e)
        }

        let user: User;
        try {
            user = await UserService.getByEmail(registerDto.email)
            if (user.confirmed) {
                return res.status(409).send({message: 'Email already in use'})
            }
        } catch (e) {
        }

        if (!user) {
            try {
                user = await UserService.create(registerDto);
            } catch (e) {
                return res.status(500).send({message: 'Could not create user'})
            }
        }

        let token: Token;
        try {
            token = await TokenService.create({name: 'register', value: user.id.toString()})
        } catch (e) {
            return res.status(500).send({message: 'Could not create token'})
        }

        try {
            await EmailService.sendRegistration({
                token: token.token,
                returnUrl: registerDto.returnUrl,
                email: user.email
            })
        } catch (e) {
            return res.status(500).send({message: 'Could not send registration email'})
        }

        return res.send({message: 'okay'})
    }

    static async registerConfirmation(req: express.Request, res: express.Response): Promise<any> {
        let token: Token
        try {
            token = await TokenService.getByToken(req.query.token as string)
            if (!token) {
                return res.status(404).send({message: 'Token not found'})
            }
        } catch (e) {
            return res.status(500).send({message: 'Could not check email'})
        }

        let user: User
        try {
            user = await UserService.getById(parseInt(token.value))
            if (user.confirmed) {
                return res.status(409).send({message: 'User already confirmed'})
            }
        } catch (e) {
            return res.status(404).send({message: 'User not found'})
        }

        try {
            user.confirmed = true
            await UserService.update(user)
        } catch (e) {
            return res.status(500).send({message: 'Could not update user'})
        }

        try {
            await TokenService.delete(token.token)
        } catch (e) {
            return res.status(500).send({message: 'Could not delete token'})
        }

        res.send({message: 'okay'})
    }

    static async registerResend(req: express.Request, res: express.Response): Promise<any> {
        const resendRegisterMailDto = plainToInstance(ResendRegisterMailDto, req.body, {excludeExtraneousValues: true});

        try {
            await validateOrReject(resendRegisterMailDto)
        } catch (e) {
            return res.status(400).send(e)
        }

        let user: User;
        try {
            user = await UserService.getByEmail(resendRegisterMailDto.email)
            if (user.confirmed) {
                return res.status(409).send({message: 'User already confirmed'})
            }
        } catch (e) {
            return res.status(404).send({message: 'User not found'})
        }

        let token: Token;
        try {
            token = await TokenService.create({name: 'register', value: user.id.toString()})
        } catch (e) {
            return res.status(500).send({message: 'Could not create token'})
        }

        try {
            await EmailService.sendRegistration({
                token: token.token,
                returnUrl: resendRegisterMailDto.returnUrl,
                email: user.email
            })
        } catch (e) {
            return res.status(500).send({message: 'Could not send registration email'})
        }

        return res.send({message: 'okay'})
    }

    static async login(req: express.Request, res: express.Response): Promise<any> {
        const loginDto: LoginDto = plainToInstance(LoginDto, req.body, {excludeExtraneousValues: true});

        try {
            await validateOrReject(loginDto)
        } catch (e) {
            return res.status(401).send({message: 'Unauthorized'})
        }

        let user: User;
        try {
            user = await UserService.getByEmail(loginDto.email)
        } catch (e) {
            return res.status(401).send({message: 'Unauthorized'})
        }

        if (!user.confirmed) {
            return res.status(401).send({message: 'Unauthorized'})
        }

        if (user.bannedUntil && user.bannedUntil > new Date()) {
            return res.status(401).send({message: 'Unauthorized', bannedUntil: user.bannedUntil})
        } else if (user.bannedUntil && user.bannedUntil <= new Date()) {
            user.bannedUntil = null
            user.loginAttempts = 0

            try {
                await UserService.update(user)
            } catch (e) {
                return res.status(500).send({message: 'Could not update user'})
            }
        }

        if (!(await comparePassword(user.password, loginDto.password))) {
            user.loginAttempts++
            if (user.loginAttempts >= appConfig.maxLoginAttempts) {
                user.bannedUntil = new Date(Date.now() + appConfig.banTime)
            }

            try {
                await UserService.update(user)
            } catch (e) {
                return res.status(500).send({message: 'Could not update user'})
            }

            return res.status(401).send({
                message: 'Unauthorized',
                bannedUntil: user.bannedUntil,
                loginAttempts: appConfig.maxLoginAttempts - user.loginAttempts
            })
        }

        try {
            user.loginAttempts = 0
            await UserService.update(user)
        } catch (e) {
            return res.status(500).send({message: 'Could not update user'})
        }

        const jwt = generateToken({id: user.id, email: user.email, role: user.role})

        return res.send(jwt)
    }
}