# Personal Expense Tracker

This version keeps the supplied frontend and connects it to an Express + PostgreSQL backend.

## Deploy on Render
1. Upload all files in this folder to the root of your GitHub repository (`expenses-tracker`).
2. In Render, choose **New + → Blueprint** and select that GitHub repository.
3. Render reads `render.yaml` and asks to create the web service and PostgreSQL database. Confirm.
4. Wait for deployment. Open the Render web-service URL.
5. Register a new account. Expenses and budgets are stored in PostgreSQL.

The backend creates its tables automatically on first start. Passwords are hashed with bcrypt and API routes require a signed login token.

## Local run
Requires Node.js 20+ and PostgreSQL. Set `DATABASE_URL` and `JWT_SECRET`, then run:
```bash
npm install
npm start
```
