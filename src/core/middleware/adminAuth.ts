// src/core/middleware/adminAuth.ts
import { Request, Response, NextFunction } from "express";

/** Keep in sync with your README role hierarchy */
export enum Role {
    User = 1,
    Moderator = 2,
    Admin = 3,
    SuperAdmin = 4,
    Owner = 5,
}

export interface JwtUser {
    id: string | number;
    email?: string;
    role: Role | number;
}

/** Ensures JWT middleware has attached req.user */
function requireUserPresent(req: Request, res: Response): JwtUser | null {
    const user = (req as any).user as JwtUser | undefined;
    if (!user) {
        res.status(401).json({ error: "Unauthorized: no user in request context" });
        return null;
    }
    return user;
}

/** Simple role check: user.role >= minRole */
export function requireRole(minRole: Role) {
    return (req: Request, res: Response, next: NextFunction) => {
        const user = requireUserPresent(req, res);
        if (!user) return;

        const roleNum = Number(user.role);
        if (Number.isNaN(roleNum) || roleNum < minRole) {
            return res.status(403).json({ error: "Forbidden: insufficient role" });
        }
        next();
    };
}

/** Prevents promoting/creating users with roles higher than the caller */
export function forbidEscalationFromBody(field: string = "role") {
    return (req: Request, res: Response, next: NextFunction) => {
        const user = requireUserPresent(req, res);
        if (!user) return;

        const desired = Number((req.body ?? {})[field]);
        if (!Number.isFinite(desired)) return next(); // nothing to check

        if (desired > Number(user.role)) {
            return res
                .status(403)
                .json({ error: "Forbidden: cannot assign a role higher than your own" });
        }
        next();
    };
}

/** Utility you can reuse in controllers when comparing two roles */
export function canActOnTarget(actorRole: number, targetRole: number) {
    return Number(actorRole) >= Number(targetRole);
}
