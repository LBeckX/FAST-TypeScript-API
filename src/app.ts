import "reflect-metadata"
import express from "express";
import cors from "cors";
import {databaseConfig} from "./config/database.config.js";

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

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});