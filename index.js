import cors from 'cors';
import express from 'express';
import cookieParser from 'cookie-parser';

import AdminRoute from './admin/AdminRoute.js';

const app = express();

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true
}));
app.use(cookieParser());
app.use(AdminRoute)

app.listen(3001, () => {
    console.log("Server running on port 3001");
});