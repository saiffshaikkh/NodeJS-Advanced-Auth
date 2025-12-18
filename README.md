# NodeJS Express Authentication & User Management

A robust, production-ready authentication boilerlate built with **Node.js**, **Express**, **TypeScript**, and **MongoDB**. It features secure JWT authentication, Google OAuth integration, email verification, and role-based access control.

## 🌟 Features

### 🔐 Advanced Authentication

- **JWT Strategy**: Dual-token architecture (Access Token + Refresh Token) for secure, seamless sessions.
- **Google OAuth**: Integrated user login/signup with Google.
- **Secure Sessions**: HttpOnly cookies for refresh tokens to prevent XSS.
- **Password Security**: Bcryptjs hashing for password storage.

### 📧 Email Integration

- **Account Verification**: Email confirmation flow on signup.
- **Password Reset**: Secure forgot/reset password workflow with expiring tokens.
- **Nodemailer**: Flexible email transport (Gmail, SMTP, etc.).

### 🛡️ Security & Validation

- **Zod Validation**: Type-safe request validation for all inputs.
- **RBAC**: Middleware-based Role-Based Access Control (Admin/User).
- **Type Safety**: Fully written in TypeScript for reliability.

## 🛠 Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: MongoDB (Mongoose)
- **Validation**: Zod
- **Auth**: DOCS, JWT, Google Auth Library

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+)
- MongoDB (Database URL)
- Google Cloud Console Project (for OAuth)

### Installation

1.  **Clone the repository**

    ```bash
    git clone <repository-url>
    cd nodejs-auth
    ```

2.  **Install Dependencies**

    ```bash
    npm install
    ```

3.  **Environment Setup**
    Create a `.env` file in the root directory:

    ```env
    PORT=3000
    NODE_ENV=development
    MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/auth-db

    # JWT Configuration
    JWT_ACCESS_SECRET=your_super_secret_access_key
    JWT_REFRESH_SECRET=your_super_secret_refresh_key

    # Google OAuth
    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

    # Email Configuration (SMTP)
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=your_email@gmail.com
    SMTP_PASS=your_app_specific_password
    EMAIL_FROM=no-reply@yourapp.com

    # App Config
    APP_URL=http://localhost:3000
    ```

4.  **Run Locally**
    ```bash
    npm run dev
    ```

## 📡 API Endpoints

### Auth (`/auth`)

| Method | Endpoint                | Description               |
| ------ | ----------------------- | ------------------------- |
| POST   | `/auth/register`        | Register new user         |
| POST   | `/auth/login`           | Login user                |
| POST   | `/auth/logout`          | Logout (clear cookies)    |
| POST   | `/auth/refresh`         | Refresh access token      |
| GET    | `/auth/verify-email`    | Verify email address      |
| POST   | `/auth/forgot-password` | Request password reset    |
| POST   | `/auth/reset-password`  | Reset password with token |
| GET    | `/auth/google`          | Start Google OAuth flow   |
| GET    | `/auth/google/callback` | Google OAuth callback     |

### User (`/user`)

_Protected Routes_

| Method | Endpoint   | Description              |
| ------ | ---------- | ------------------------ |
| GET    | `/user/me` | Get current user profile |

### Admin (`/admin`)

_Protected & Admin Role Only_

| Method | Endpoint    | Description                     |
| ------ | ----------- | ------------------------------- |
| GET    | `/admin/me` | List all users (Dashboard view) |

## 📁 Project Structure

```bash
src/
├── config/         # Database connection
├── controllers/    # Request handlers (Auth)
├── lib/            # Utilities (Email, Token helpers)
├── middleware/     # Auth & RBAC Middleware
├── models/         # Mongoose Models
├── routes/         # API Route definitions
├── app.ts          # Express App setup
└── server.ts       # Server entry point
```

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## 📄 License

This project is licensed under the ISC License.
