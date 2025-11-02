// src/controllers/adminController.ts
import { Request, Response } from "express";
import { canActOnTarget } from "../core/middleware/adminAuth";

type Ok = { ok: true; data?: unknown; message?: string };
type Err = { ok: false; error: string };

function ok(res: Response, data?: unknown, message?: string) {
    const body: Ok = { ok: true, data, message };
    return res.status(200).json(body);
}

function notImpl(res: Response, hint: string) {
    const body: Err = { ok: false, error: `Not implemented yet: ${hint}` };
    return res.status(501).json(body);
}

/** GET /admin/users */
export async function listUsers(req: Request, res: Response) {
    // Stubbed pagination (page, limit)
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 25));
    // Return an empty list for now so Postman tests can be written
    return ok(res, { page, limit, total: 0, items: [] });
}

/** GET /admin/users/search?query=... */
export async function searchUsers(req: Request, res: Response) {
    const q = String(req.query.query || "").trim();
    return ok(res, { query: q, total: 0, items: [] });
}

/** GET /admin/users/:id */
export async function getUser(req: Request, res: Response) {
    const id = req.params.id;
    // Placeholder user example shape for front-end wiring
    return ok(res, { id, email: "example@domain.com", role: 1, active: true });
}

/** POST /admin/users/create */
export async function createUser(req: Request, res: Response) {
    // NOTE: adminAuth.forbidEscalationFromBody already prevents higher-role creation.
    // Implement actual DB insert here later.
    return ok(res, { created: req.body }, "User creation stub");
}

/** PUT /admin/users/:id */
export async function updateUser(req: Request, res: Response) {
    // If you need to block lowering/raising roles beyond actor, do it here too.
    return ok(res, { id: req.params.id, updates: req.body }, "Update stub");
}

/** DELETE /admin/users/:id (soft delete) */
export async function deleteUser(req: Request, res: Response) {
    return ok(res, { id: req.params.id, deleted: true }, "Soft delete stub");
}

/** PUT /admin/users/:id/password */
export async function adminResetPassword(req: Request, res: Response) {
    const id = req.params.id;
    // TODO: force-reset token or direct password set
    return ok(res, { id }, "Admin password reset stub");
}

/** PUT /admin/users/:id/role */
export async function changeRole(req: Request, res: Response) {
    const actor = (req as any).user?.role ?? 0;
    const targetCurrentRole = Number(req.body.currentRole ?? 1); // supply if you have it
    const desired = Number(req.body.role);

    if (!Number.isFinite(desired)) {
        return res.status(400).json({ ok: false, error: "role is required (number)" });
    }
    if (desired > Number(actor)) {
        return res
            .status(403)
            .json({ ok: false, error: "Cannot assign a role higher than your own" });
    }
    if (!canActOnTarget(Number(actor), targetCurrentRole)) {
        return res
            .status(403)
            .json({ ok: false, error: "Cannot modify a user with higher role" });
    }
    return ok(res, { id: req.params.id, role: desired }, "Role change stub");
}

/** GET /admin/users/stats/dashboard */
export async function dashboardStats(_req: Request, res: Response) {
    // Return zeros so charts can render
    return ok(res, {
        totals: { users: 0, active: 0, pendingVerification: 0, admins: 0 },
        last7d: [],
    });
}
