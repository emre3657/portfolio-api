# Portfolio API

This is the backend service for the portfolio contact form.
It provides a small Express API that validates contact requests and sends email via Resend.

## Features

- Express server with TypeScript
- security middleware: `helmet`
- CORS filtering for allowed domains
- rate limiting on contact submissions
- Resend email delivery for admin notification and auto-reply

## Endpoints

- `GET /api/build`
  - health check endpoint
  - returns JSON status
- `POST /api/contact`
  - contact form submission endpoint
  - expects JSON body with `name`, `email`, `subject`, `message`, and `honeypot`
  - blocks invalid referers/origins and rate-limits requests

## Environment

Required environment variables:

- `RESEND_API_KEY` - API key for Resend email service
- `PORT` - optional, default is `3000`
- `NODE_ENV` - optional, used to enable HSTS in production

## Scripts

- `npm run dev` - start development server with `ts-node-dev`
- `npm run build` - compile TypeScript into `dist`
- `npm run start` - run the compiled production server

## Install

```bash
npm install
```

## Run

```bash
npm run dev
```
