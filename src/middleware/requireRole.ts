import { NextFunction, Request, Response } from "express";

function requireRole(role: "user" | "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as any;
    const authUser = authReq.user;
    if (!authUser) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }
    if (authUser.role !== role) {
      return res.status(401).json({
        message: "Unauthorized Role",
      });
    }
    next();
  };
}

export default requireRole;
