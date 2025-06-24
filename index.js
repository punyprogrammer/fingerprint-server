import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import crypto from "crypto"; // Removed invalid { hash } import

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Middleware for logging request/response
app.use((req, res, next) => {
  console.log(`→ [${req.method}] ${req.originalUrl}`);
  console.log("→ Headers:", JSON.stringify(req.headers));

  if (req.body && Object.keys(req.body).length > 0) {
    console.log("→ Body:", JSON.stringify(req.body));
  }

  const originalSend = res.send;
  res.send = function (body) {
    console.log(
      `← [${req.method}] ${req.originalUrl} - Status: ${res.statusCode}`
    );
    console.log("← Response Body:", body);
    return originalSend.call(this, body);
  };

  next();
});

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

function stableStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// Fingerprint API
app.post("/api/fingerprint", async (req, res) => {
  const clientData = req.body;

  const userAgent = req.headers["user-agent"];
  const forwardedProto = req.headers["x-forwarded-proto"] || "http";
  const forwardedPort =
    req.headers["x-forwarded-port"] || req.socket.remotePort;

  const serverMeta = {
    userAgent, // Browser/OS/device
    protocol: forwardedProto, // http or https
    port: forwardedPort, // client port (proxy-aware)
    language: req.headers["accept-language"], // preferred languages
    accept: req.headers["accept"], // accepted MIME types
    dnt: req.headers["dnt"], // Do Not Track signal
    httpVersion: req.httpVersion, // HTTP/1.1 or 2
    secChUa: req.headers["sec-ch-ua"], // browser brands
    secChUaMobile: req.headers["sec-ch-ua-mobile"], // mobile or not
    secChUaPlatform: req.headers["sec-ch-ua-platform"], // OS
    referer: req.headers["referer"], // referring page
    origin: req.headers["origin"], // CORS origin
  };

  const fingerprintPayload = {
    ...clientData,
    serverMeta,
  };

  const combinedHash = crypto
    .createHash("sha256")
    .update(JSON.stringify(stableStringify(fingerprintPayload)))
    .digest("hex");

  fingerprintPayload.hash = combinedHash;
  fingerprintPayload.last_visited = new Date().toISOString();

  const { error } = await supabase
    .from("fingerprints")
    .insert([fingerprintPayload]);

  if (error?.code === "23505") {
    return res.status(200).json({ hash: combinedHash });
  }

  if (error) {
    console.error("Insert error:", error);
    return res.status(500).json({ message: "Error saving fingerprint" });
  }

  res.status(201).json({ message: "Fingerprint saved", hash: combinedHash });
});

// Get all fingerprints
app.get("/api/fingerprints", async (req, res) => {
  const { data, error } = await supabase
    .from("fingerprints")
    .select("*")
    .order("last_visited", { ascending: false });

  if (error) {
    console.error("Fetch error:", error);
    return res.status(500).json({ message: "Error fetching fingerprints" });
  }

  res.status(200).json(data);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
