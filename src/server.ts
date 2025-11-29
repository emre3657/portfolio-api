import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import express from "express";
import type { Request, Response } from "express";
import { Resend } from "resend";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

// trust upstream
app.set("trust proxy", 3);

// global
app.use(helmet());

// HSTS (only production)
if (process.env.NODE_ENV === "production") {
  app.use(
    helmet.hsts({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    })
  );
}

// Allow only these origins
const whitelist = [
  "https://emreekincidev.com", // production domain
  "http://localhost:5173", // dev vite
];

const corsOptions = {
  origin: function (
    origin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void
  ) {
    // Postman, curl or request that not include the origin
    if (!origin) return callback(null, true);

    if (whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));

// JSON
app.use(express.json());

// rateLimiter
const rateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3, // max 3 request in 1 minute
  message: {
    status: "error",
    message: "Lütfen tekrar denemeden önce biraz bekleyin.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Referer/Origin control
function isAllowedReferer(req: Request) {
  const referer = req.get("referer") || "";
  const origin = req.get("origin") || "";

  const allowed = ["https://emreekincidev.com", "http://localhost:5173"];

  return allowed.some(
    (url) => referer.startsWith(url) || origin.startsWith(url)
  );
}

app.get("/api/build", (req: Request, res: Response) => {
  return res
    .status(200)
    .json({ status: "success", message: "server is active" });
});

app.post("/api/contact", rateLimiter, async (req: Request, res: Response) => {
  if (!isAllowedReferer(req)) {
    console.warn("[INVALID REQUEST]", {
      path: req.path,
      referer: req.headers.referer,
      ip: req.ip,
      at: new Date().toISOString(),
    });

    return res.status(403).json({
      status: "error",
      message: "Geçersiz istek!",
      code: "INVALID_REQUEST",
    });
  }

  type Payload = {
    name: string;
    email: string;
    subject: string;
    message: string;
    honeypot: string;
  };

  const { name, email, subject, message, honeypot }: Payload = req.body || {};

  // Honeypot bot check
  if (honeypot) {
    console.warn("[HONEYPOT TRIGGERED]", {
      email,
      ip: req.ip,
      at: new Date().toISOString(),
    });

    return res.status(200).json({ status: "success" });
  }

  // Basic validation
  if (!name || !email || !subject || !message) {
    console.warn("[BAD REQUEST]", {
      body: req.body,
      missingFields: { name, email, subject, message },
      at: new Date().toISOString(),
    });

    return res.status(400).json({
      status: "error",
      message: "Tüm alanlar zorunlu!",
      code: "BAD_REQUEST",
    });
  }

  console.log("[CONTACT RECEIVED]", {
    name,
    email,
    subject,
    ip: req.ip,
    at: new Date().toISOString(),
  });

  try {
    // 1) Mail to admin (me)
    const { data: adminMail, error: adminError } = await resend.emails.send({
      from: "Portfolio Contact <contact@mail.emreekincidev.com>",
      to: "emree3657@gmail.com",
      subject: `Yeni Mesaj: ${subject}`,
      html: `
        <p><strong>İsim:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Konu:</strong> ${subject}</p>
        <p><strong>Mesaj:</strong><br/>${String(message).replace(
          /\n/g,
          "<br/>"
        )}</p>
      `,
    });

    if (adminError) {
      console.error("[ADMIN MAIL FAILED]", {
        name,
        email,
        reason: adminError,
        at: new Date().toISOString(),
      });

      return res.status(502).json({
        status: "error",
        message:
          "Şu anda mesajını iletemiyorum. Lütfen biraz sonra tekrar dene.",
        code: "ADMIN_MAIL_FAILED",
      });
    }

    console.log("[ADMIN MAIL SUCCESS]", {
      mailId: adminMail?.id,
      from: email,
      at: new Date().toISOString(),
    });

    // 2) Auto-reply mail
    const { data: autoMail, error: autoError } = await resend.emails.send({
      from: "Emre Ekinci <contact@mail.emreekincidev.com>",
      to: email,
      subject: "Mesajınız alındı ✔",
      html: `
        <p>Merhaba <strong>${name}</strong>,</p>
        <p>İletişim formunuz elime ulaştı. En kısa sürede dönüş sağlayacağım.</p>
        <hr>
        <p><em>Gönderdiğiniz mesaj:</em></p>
        <p>${String(message).replace(/\n/g, "<br/>")}</p>
        <br/>
        <p>İyi günler dilerim.</p>
      `,
    });

    if (autoError) {
      console.error("[AUTO-REPLY FAILED]", {
        email,
        reason: autoError,
        adminMailId: adminMail?.id,
        at: new Date().toISOString(),
      });

      return res.status(200).json({
        status: "warning",
        message:
          "Mesajın bana ulaştı fakat e-posta adresine otomatik yanıt gönderemedim. Adresi kontrol edebilirsin.",
        code: "AUTO_REPLY_FAILED",
        meta: {
          adminMailId: adminMail?.id,
        },
      });
    }

    console.log("[AUTO-REPLY SUCCESS]", {
      mailId: autoMail?.id,
      to: email,
      at: new Date().toISOString(),
    });

    // Final response
    return res.status(200).json({
      status: "success",
      message: "Mesaj iletildi. Otomatik yanıt gönderildi.",
      code: "OK",
      meta: {
        adminMailId: adminMail?.id,
        autoMailId: autoMail?.id,
      },
    });
  } catch (error) {
    console.error("[UNEXPECTED ERROR]", {
      error,
      at: new Date().toISOString(),
    });

    return res.status(500).json({
      status: "error",
      message: "Beklenmeyen bir hata oluştu.",
      code: "UNEXPECTED_ERROR",
    });
  }
});

app.listen(port, () => {
  console.log(`Portfolio API running at http://localhost:${port}`);
});
