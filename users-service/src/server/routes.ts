import { Express } from "express";
import { getConnection, getRepository } from "typeorm";
import config from "config";
import omit from "lodash.omit";

import User from "#root/db/entities/User";
import UserSession from "#root/db/entities/UserSessions";
import generateUUID from "#root/helpers/generateUUID";
import hashPassword from "#root/helpers/hashPassword";
import passwordCompareSync from "#root/helpers/passwordCompareSync";
import dayjs from "dayjs";

const USER_SESSION_EXPIRY_HOURS = <number>(
  config.get("USER_SESSION_EXPIRY_HOURS")
);

const setupRoutes = (app: Express) => {
  const connection = getConnection();
  const userRepository = getRepository(User);
  const userSessionRepository = getRepository(UserSession);

  // login user
  app.post("/sessions", async (req, res, next) => {
    if (!req.body.username || !req.body.password) {
      return next(new Error("Invalid body!"));
    }

    try {
      const user = await userRepository.findOne(
        {
          username: req.body.username,
        },
        {
          select: ["id", "passwordHash"],
        }
      );

      if (!user) return next(new Error("Invalid username!"));

      if (!passwordCompareSync(req.body.password, user.passwordHash)) {
        return next(new Error("Invalid password!"));
      }

      const expiresAt = dayjs()
        .add(USER_SESSION_EXPIRY_HOURS, "hour")
        .toISOString();

      const sessionToken = generateUUID();

      const userSession = {
        expiresAt,
        id: sessionToken,
        userId: user.id,
      };

      await connection
        .createQueryBuilder()
        .insert()
        .into(UserSession)
        .values([userSession])
        .execute();

      return res.json(userSession);
    } catch (err) {
      return next(err);
    }
  });

  // delete session || logout
  app.delete("/sessions/:sessionId", async (req, res, next) => {
    try {
      const userSession = await userSessionRepository.findOne(
        req.params.sessionId
      );
      if (!userSession) return next(new Error("Invalid session ID!"));

      await userSessionRepository.remove(userSession);
      return res.end()
    } catch (error) {
      return next(error);
    }
  });

  // check login
  app.get("/sessions/:sessionId", async (req, res, next) => {
    try {
      const userSession = await userSessionRepository.findOne(
        req.params.sessionId
      );
      if (!userSession) return next(new Error("Invalid session ID!"));

      return res.json(userSession)
    } catch (error) {
      return next(error);
    }
  });

  // Create a user
  app.post("/users", async (req, res, next) => {
    if (!req.body.username || !req.body.password) {
      return next(new Error("Invalid body!"));
    }

    try {
      const newUser = {
        id: generateUUID(),
        passwordHash: hashPassword(req.body.password),
        username: req.body.username,
      };

      await connection.createQueryBuilder().insert().into(User).values([newUser]).execute();

      return res.json(omit(newUser, ["passwordHash"]));
    } catch (err) {
      return next(err);
    }
  });

  // get a user
  app.get("/users/:userId", async (req, res, next) => {
    try {
      const user = await userRepository.findOne(req.params.userId);
      if (!user) return next(new Error("Invalid User ID!"));

      res.json(user);
      return;
    } catch (error) {
      return next(error);
    }
  });
};

export default setupRoutes;
