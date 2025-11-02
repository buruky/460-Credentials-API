// src/routes/index.ts
import { Router } from "express";
import { openRoutes } from "./open";
import { closedRoutes } from "./closed";
import adminRoutes from "./admin"; // ✅ import your admin router
import { checkToken } from '@middleware'; // ✅ verify path matches your structure

const routes: Router = Router();

// Mount open (public) routes
routes.use("", openRoutes);

// Mount closed (JWT-protected) routes
routes.use("", closedRoutes);

// ✅ Mount admin routes (JWT + admin role required)
routes.use("/admin", checkToken, adminRoutes);

export { routes };
