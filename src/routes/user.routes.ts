import express from "express";
import {UserController} from "../controller/user.controller.js";

export const userRouter = express.Router();
userRouter.get('/me', UserController.me);

export default userRouter;