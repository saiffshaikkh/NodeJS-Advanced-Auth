import { connectToDB } from "./config/db";
import dotenv from "dotenv";
import http from "http";
import app from "./app";

dotenv.config();

async function startServer() {
  await connectToDB();
  const server = http.createServer(app);

  server.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Error while starting the server", err);
  process.exit(1);
});
