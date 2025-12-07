// src/routes/closed/index.ts
import express, { Router } from "express";
import { AuthController, VerificationController } from "@controllers";
import {
    checkToken,
    validatePasswordChange,
    validatePhoneSend,
    validatePhoneVerify
} from "@middleware";

const closedRoutes: Router = express.Router();

// All closed routes require authentication
closedRoutes.use(checkToken);

// Password change (requires old password)
closedRoutes.post("/auth/user/password/change", validatePasswordChange, AuthController.changePassword);

// Phone verification routes
closedRoutes.post("/auth/verify/phone/send", validatePhoneSend, VerificationController.sendSMSVerification);
closedRoutes.post("/auth/verify/phone/verify", validatePhoneVerify, VerificationController.verifySMSCode);

// Email verification (sending email) – requires user to be logged in
closedRoutes.post("/auth/verify/email/send", VerificationController.sendEmailVerification);

export { closedRoutes };
