import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import express, { type Request } from "express";
import { Resend } from "resend";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

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

app.get("/api/build", async (req, res) => {
  return res.status(200).json({ status: "success", message: "Sunucu aktif" });
});

app.post("/api/contact", rateLimiter, async (req, res) => {
  if (!isAllowedReferer(req)) {
    return res.status(403).json({
      status: "error",
      message: "Geçersiz istek.",
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
    return res.status(200).json({ status: "success" });
  }

  if (!name || !email || !subject || !message) {
    return res.status(400).json({
      status: "error",
      message: "Tüm alanlar zorunlu.",
    });
  }

  try {
    // mait to me
    await resend.emails.send({
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

    // oto mail
    await resend.emails.send({
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

    return res.status(200).json({
      status: "success",
      message: "Mesaj iletildi. Otomatik yanıt gönderildi.",
    });
  } catch (error) {
    console.error("Resend error:", error);

    return res.status(500).json({
      status: "error",
      message: "Mail gönderilemedi.",
    });
  }
});

app.listen(port, () => {
  console.log(`Portfolio API running at http://localhost:${port}`);
});
