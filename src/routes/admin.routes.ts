import { Router } from "express";
import requireAuth from "../middleware/requireAuth";
import requireRole from "../middleware/requireRole";
import { Request, Response } from "express";
import { User } from "../models/user.model";

const router = Router();

router.get(
  "/me",
  requireAuth,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    try {
      const users = await User.find(
        {},
        {
          email: 1,
          name: 1,
          role: 1,
          isEmailVerified: 1,
          twoFactorEnabled: 1,
          createdAt: 1,
        }
      ).sort({ createdAt: -1 });

      const mappedUsers = users.map((user) => {
        return {
          email: user.email,
          name: user.name,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
          createdAt: user.createdAt,
        };
      });
      return res.json({ users: mappedUsers });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        message: "Internal Server Error",
      });
    }
  }
);

export default router;
