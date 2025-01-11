import express from "express";
import {AuthController} from "../controller/auth.controller.js";

export const authRouter = express.Router();
authRouter.post('/login', (req, res) => {
    res.send('login')
});
authRouter.post('/register', AuthController.register);
authRouter.post('/register/confirmation', AuthController.registerConfirmation);
authRouter.post('/register/resend', AuthController.registerResend);
authRouter.post('/password-reset', (req, res) => {
    res.send('password reset')
});
authRouter.post('/password-reset/confirmation', (req, res) => {
    res.send('password reset confirmation')
});
export default authRouter;