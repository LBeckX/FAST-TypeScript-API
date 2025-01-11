import dotenv from "dotenv"

dotenv.config()

export const appConfig = {
    secret: process.env.SECRET_KEY,
    jwtExpire: '1d',
    maxLoginAttempts: 5,
    banTime: 60 * 1000,
}