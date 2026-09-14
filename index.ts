import express from "express";
import app from "./artifacts/api-server/src/app";

const server = express();

server.use(app);

export default server;
