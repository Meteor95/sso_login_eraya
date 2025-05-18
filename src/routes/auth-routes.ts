import { Elysia } from "elysia";
import { loginSSO, registerSSO } from "@controllers/auth/auth-controller";

export const authRoutes = new Elysia();

authRoutes.post("/login", ({ body, set }) => loginSSO({ body, set }));
authRoutes.post("/register", ({ body, set }) => registerSSO({ body, set }));