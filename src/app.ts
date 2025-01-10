import express from "express";
import cors from "cors";

const port = 3001;
const app = express();

app.use(express.text());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cors());

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});