import nodemailer from "nodemailer";

export async function sendMail(to: string, subject: string, html: string) {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_PORT ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS ||
    !process.env.EMAIL_FROM
  ) {
    throw new Error("SMTP configuration is missing");
  }

  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT, 10); // Convert to number
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.EMAIL_FROM;

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: false, // true for 465, false for other ports
    auth: {
      user,
      pass,
    },
  });

  // Actually send the email
  await transporter.sendMail({
    from,
    to,
    subject,
    html,
  });
}
