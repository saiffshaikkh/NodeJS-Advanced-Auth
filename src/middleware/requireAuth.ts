import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";
import { NextFunction, Request, Response } from "express";

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "No authorization header provided",
      });
    }
    const token = authHeader.split("Bearer ")[1];
    const payload = verifyAccessToken(token);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        message: "Token version mismatch",
      });
    }

    const authReq = req as any;
    authReq.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      twoFactorEnabled: user.twoFactorEnabled,
    };
    next();
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export default requireAuth;