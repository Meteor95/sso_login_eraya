import { Elysia } from "elysia";
import { loginSSO, registerSSO } from "@controllers/auth/auth-controller";

export const authRoutes = new Elysia().group("/auth", (app) =>
  app
    .post("/login", ({ body, set }) => loginSSO({ body, set }))
    .post("/register", ({ body, set }) => registerSSO({ body, set }))
);