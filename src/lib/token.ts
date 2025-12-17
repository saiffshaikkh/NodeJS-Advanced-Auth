import jwt from "jsonwebtoken";

export function createAccessToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number
) {
  const payload = {
    sub: userId,
    role,
    tokenVersion,
  };

  const token = jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "30m",
  });

  return token;
}

export function createRefreshToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number
) {
  const payload = {
    sub: userId,
    role,
    tokenVersion,
  };

  const token = jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: "7d",
  });

  return token;
}

export function verifyRefreshToken(token: string) {
  const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    sub: string;
    role: "user" | "admin";
    tokenVersion: number;
  };
  return payload;
}

export function verifyAccessToken(token: string) {
  const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: "user" | "admin";
    tokenVersion: number;
  };
  return payload;
}
