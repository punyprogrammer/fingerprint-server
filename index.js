import http from "http";
import https from "https";
import { readFileSync } from "fs";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import crypto from "crypto";
import { parse } from "url";

// Load .env variables
dotenv.config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
const setCORSHeaders = (res) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // Or specify exact origin like "https://your-react-app.com"
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
};
function stableStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function collectRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

const requestHandler = async (req, res) => {
  const { pathname } = parse(req.url, true);
  // Set CORS headers for every request
  setCORSHeaders(res);

  // Handle preflight OPTIONS request
  if (req.method === "OPTIONS") {
    res.writeHead(200);
    return res.end();
  }
  if (req.method === "POST" && pathname === "/api/fingerprint") {
    try {
      const clientData = await collectRequestBody(req);

      const socket = req.socket || req.connection;
      const tlsInfo = socket.getPeerCertificate?.() || {};
      const cipher = socket.getCipher?.() || {};
      const serverMeta = {
        userAgent: req.headers["user-agent"], // Full User-Agent string — browser, OS, device info
        language: req.headers["accept-language"], // Preferred languages sent by the browser (e.g., "en-US,en;q=0.9")
        accept: req.headers["accept"], // MIME types the browser is willing to receive
        dnt: req.headers["dnt"], // "Do Not Track" header — indicates user's tracking preferences ("1" means do not track)
        httpVersion: req.httpVersion, // HTTP protocol version used (e.g., "1.1" or "2.0")

        // User-Agent Client Hints — finer-grained and privacy-preserving browser info
        secChUa: req.headers["sec-ch-ua"], // Lists browser brand and version (e.g., `"Chromium";v="114", "Google Chrome";v="114"`)
        secChUaMobile: req.headers["sec-ch-ua-mobile"], // Indicates if the device is mobile (`"?1"` for mobile, `"?0"` for desktop)
        secChUaPlatform: req.headers["sec-ch-ua-platform"], // Operating system/platform (e.g., `"macOS"`, `"Android"`)

        referer: req.headers["referer"], // The previous page that linked to this request (can be used to validate navigation origin)
        origin: req.headers["origin"], // The origin (protocol + domain) of the request — helps with CORS or request source validation

        // TLS/SSL-level details for connection fingerprinting
        tlsProtocol: cipher.version || "n/a", // TLS version used in the connection (e.g., "TLSv1.3")
        tlsCipher: cipher.name || "n/a", // Specific TLS cipher suite used (e.g., "TLS_AES_128_GCM_SHA256")

        peerCertSubject: tlsInfo.subject || {}, // Subject of the client certificate (if mutual TLS is used)
        peerCertIssuer: tlsInfo.issuer || {}, // Issuer of the client certificate (if mutual TLS is used)
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

      if (error && error.code !== "23505") {
        console.error("Insert error:", error);
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ message: "Error saving fingerprint" }));
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ hash: combinedHash }));
    } catch (err) {
      console.error("Error handling /api/fingerprint:", err);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Invalid request" }));
    }
  } else if (req.method === "GET" && pathname === "/api/fingerprints") {
    const { data, error } = await supabase
      .from("fingerprints")
      .select("*")
      .order("last_visited", { ascending: false });

    if (error) {
      console.error("Fetch error:", error);
      res.writeHead(500, { "Content-Type": "application/json" });
      return res.end(
        JSON.stringify({ message: "Error fetching fingerprints" })
      );
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  } else {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "Not Found" }));
  }
};

const PORT = process.env.PORT || 4000;

// Use HTTPS only if you provide cert/key; else fallback to HTTP
if (process.env.USE_HTTPS === "true") {
  const options = {
    key: readFileSync("./certs/key.pem"),
    cert: readFileSync("./certs/cert.pem"),
  };

  https.createServer(options, requestHandler).listen(PORT, () => {
    console.log(`HTTPS Server running on port ${PORT}`);
  });
} else {
  http.createServer(requestHandler).listen(PORT, () => {
    console.log(`HTTP Server running on port ${PORT}`);
  });
}
