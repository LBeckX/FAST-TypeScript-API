import {User} from "../entitites/user.entity.js";
import express from "express";

export type ExpressUserRequest = {
    user: User
} & express.Request;