import express from "express";

// @ts-ignore - bundled ESM module has no type declarations
const appPromise = import("./artifacts/api-server/dist/vercel.mjs");

const server = express();

server.use(async (req, res, next) => {
  try {
    const { default: app } = await appPromise;
    return app(req, res, next);
  } catch (error) {
    next(error);
  }
});

export default server;
