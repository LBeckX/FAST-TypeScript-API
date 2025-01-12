import "reflect-metadata"
import express from "express";
import cors from "cors";
import {databaseConfig} from "./config/database.config.js";
import authRouter from "./routes/auth.routes.js";
import {needAuth} from "./middleware/auth.middleware.js";
import userRouter from "./routes/user.routes.js";

const port = 3001;
const app = express();

try {
    await databaseConfig.initialize()
    console.log('Database initialized')
} catch (e) {
    console.error(e)
    process.exit(1)
}

app.use(express.text());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cors());

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/user', needAuth, userRouter);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});