import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { comparePassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendMail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI; // <--- This must be the callback URL

  // ...
  return new OAuth2Client(clientId, clientSecret, redirectUri);
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid Data",
        errors: result.error.flatten(),
      });
    }

    const { email, password, name } = result.data;
    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
      });
    }

    const passwordHash = await hashPassword(password);
    const newlyCreatedUser = await User.create({
      email: normalizedEmail,
      passwordHash,
      name,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser._id,
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendMail(
      newlyCreatedUser.email,
      "Verify Email",
      `<p>Click <a href="${verifyUrl}">here</a> to verify your email</p>
        <p><a href="${verifyUrl}">${verifyUrl}</a></p>`
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newlyCreatedUser.id,
        email: newlyCreatedUser.email,
        name: newlyCreatedUser.name,
        role: newlyCreatedUser.role,
        isEmailVerified: newlyCreatedUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({
        message: "No token provided",
      });
    }

    const payload = jwt.verify(token as string, process.env.JWT_ACCESS_SECRET!);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }
    if (user.isEmailVerified) {
      return res.status(400).json({
        message: "Email already verified",
      });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({
      message: "Email verified successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid Data",
        errors: result.error.flatten(),
      });
    }

    const { email, password } = result.data;
    const normalizedEmail = email.toLocaleLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const isPasswordValid = await comparePassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid password",
      });
    }

    if (!user.isEmailVerified) {
      return res.status(401).json({
        message: "Email not verified",
      });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies.refreshToken as string;

    if (!token) {
      res.status(401).json({
        message: "No refresh token provided",
      });
    }

    const payload = verifyRefreshToken(token);
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
    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Refresh successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  try {
    res.clearCookie("refreshToken", { path: "/" });
    return res.status(200).json({
      message: "Logout successful",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  try {
    const { email } = req.body as { email?: string };
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }
    const normalizedEmail = email.toLocaleLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;
    await sendMail(
      user.email,
      "Reset Password",
      `<p>Click <a href="${resetUrl}">here</a> to reset your password</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>`
    );
    return res.status(200).json({
      message: "Reset password email sent successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  try {
    const { token, password } = req.body as {
      token?: string;
      password?: string;
    };
    if (!token || !password) {
      return res.status(400).json({
        message: "Token and password are required",
      });
    }
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }
    user.passwordHash = await hashPassword(password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion++;
    await user.save();
    return res.status(200).json({
      message: "Password reset successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function googleAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const authUrl = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });
    console.log("DEBUG: Generated Auth URL:", authUrl);
    return res.redirect(authUrl);
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string | undefined;

  // 1. Validation Logic
  if (!code) {
    return res.status(400).json({
      message: "Code is required",
    });
  } // <--- Close the IF block here

  // 2. Main Logic (Runs if code exists)
  try {
    const client = getGoogleClient();
    const { tokens } = await client.getToken(code);

    console.log(tokens, code, "code");
    if (!tokens.id_token) {
      return res.status(400).json({
        message: "ID token is required",
      });
    }
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });
    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({
        message: "Invalid email or email verification",
      });
    }

    const normalizedEmail = email.toLocaleLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const hashedPassword = await hashPassword(randomPassword);
      user = await User.create({
        email: normalizedEmail,
        passwordHash: hashedPassword,
        name: payload?.given_name,
        isEmailVerified: true,
        role: "user",
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Refresh successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}
