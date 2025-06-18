import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// Supabase config
const supabaseUrl = "https://indrsxapyxsyxoqcefta.supabase.co"; // replace
const supabaseKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImluZHJzeGFweXhzeXhvcWNlZnRhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAyMzc3NzUsImV4cCI6MjA2NTgxMzc3NX0.ht6N7FJdEf3dYROB_ulFejSp2THlTU8_6cujPIp5-_0"; // replace
const supabase = createClient(supabaseUrl, supabaseKey);

app.post("/api/fingerprint", async (req, res) => {
  const data = req.body;
  const { hash } = data;

  // Try inserting the fingerprint directly
  const { error } = await supabase.from("fingerprints").insert([
    {
      ...data,
      last_visited: new Date().toISOString(),
    },
  ]);

  if (error) {
    // If duplicate hash, update instead
    if (error.code === "23505") {
      // 23505 = unique_violation in PostgreSQL
      const { data: existing, error: fetchErr } = await supabase
        .from("fingerprints")
        .select("id")
        .eq("hash", hash)
        .single();

      if (existing) {
        const { error: updateErr } = await supabase
          .from("fingerprints")
          .update({ last_visited: new Date().toISOString() })
          .eq("id", existing.id);

        if (updateErr) {
          console.error("Update error:", updateErr);
          return res
            .status(500)
            .json({ message: "Error updating fingerprint" });
        }

        return res.status(200).json({ message: "Fingerprint updated" });
      }

      return res
        .status(500)
        .json({ message: "Fingerprint conflict but not found" });
    }

    console.error("Insert error:", error);
    return res.status(500).json({ message: "Error saving fingerprint" });
  }

  res.status(201).json({ message: "Fingerprint saved" });
});
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
// Start server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
