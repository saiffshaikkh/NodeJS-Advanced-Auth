import { Router } from "express";
import requireAuth from "../middleware/requireAuth";
import { Request, Response } from "express";

const router = Router();

router.get("/me", requireAuth, (req: Request, res: Response) => {
    const authReq = req as any;
    const user = authReq.user;
    return res.json({
        message: "User data",
        user,
    });
});

export default router;