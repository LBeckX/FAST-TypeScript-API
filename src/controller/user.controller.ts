import {ExpressUserRequest} from "../types/express.types.js";
import express from "express";
import {UserService} from "../services/user.service.js";

export class UserController {
    static async me(req: ExpressUserRequest, res: express.Response): Promise<any> {
        return res.send(UserService.getSafeUser(req.user))
    }
}