// src/routes/admin/index.ts
import { Router } from "express";
import { requireRole, forbidEscalationFromBody, Role } from "../../core/middleware/adminAuth";
import {
    listUsers,
    searchUsers,
    getUser,
    createUser,
    updateUser,
    deleteUser,
    adminResetPassword,
    changeRole,
    dashboardStats,
} from "../../controllers/adminController";

// IMPORTANT: the JWT check is added where you mount this router (see step 4).
const router = Router();

// READ
router.get("/users", requireRole(Role.Admin), listUsers);
router.get("/users/search", requireRole(Role.Admin), searchUsers);
router.get("/users/stats/dashboard", requireRole(Role.Admin), dashboardStats);
router.get("/users/:id", requireRole(Role.Admin), getUser);

// WRITE
router.post(
    "/users/create",
    requireRole(Role.Admin),
    forbidEscalationFromBody("role"),
    createUser
);

router.put("/users/:id", requireRole(Role.Admin), updateUser);

router.put(
    "/users/:id/password",
    requireRole(Role.Admin),
    adminResetPassword
);

router.put(
    "/users/:id/role",
    requireRole(Role.Admin),
    forbidEscalationFromBody("role"),
    changeRole
);

router.delete("/users/:id", requireRole(Role.Admin), deleteUser);

export default router;
