import jwt from 'jsonwebtoken';
import {appConfig} from "../config/app.config.js";
import {User} from "../entitites/user.entity.js";

export function generateToken(payload: any): string {
    return jwt.sign(payload, appConfig.secret, {
        expiresIn: appConfig.jwtExpire,
    });
}

export function validateToken(jwtStr: string) {
    return jwt.verify(jwtStr, appConfig.secret);
}

export function decodeToken(jwtStr: string) {
    return jwt.decode(jwtStr, {json: true}) as User;
}