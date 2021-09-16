import bodyParser from "body-parser";
import cors from "cors";
import express, { Request, Response, NextFunction } from "express";

import accessEnv from "#root/helpers/accessEnv";
import setupRoutes from "./routes";

const PORT = parseInt(accessEnv("PORT", "7101"), 10);

const startServer = () => {
  const app = express();
  app.use(bodyParser.json());
  app.use(
    cors({
      origin: (origin, cb) => cb(null, true),
      credentials: true,
    })
  );

  setupRoutes(app);

  // Error Handler
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    res.status(500).json({ message: err.message });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.info(`Users service is Listening on ${PORT}`);
  });
};

export default startServer;
