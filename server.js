const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require("discord.js");

const app = express();
app.use(express.json({ limit: "32kb" }));
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "licenses.json");
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || "";
const PRIVATE_XML = process.env.LICENSE_PRIVATE_XML || "";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");

function b64url(buf) { return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"); }
function fromB64url(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Buffer.from(s, "base64"); }
function xmlParam(xml, name) {
  const m = xml.match(new RegExp("<" + name + ">([^<]+)</" + name + ">"));
  if (!m) throw new Error("Missing RSA parameter: " + name);
  return b64url(Buffer.from(m[1], "base64"));
}
function privateKeyObject() {
  if (!PRIVATE_XML || PRIVATE_XML.includes("PASTE_EXISTING")) throw new Error("LICENSE_PRIVATE_XML is not configured on the server.");
  const names = ["Modulus","Exponent","P","Q","DP","DQ","InverseQ","D"];
  const jwk = { kty: "RSA", n: xmlParam(PRIVATE_XML,"Modulus"), e: xmlParam(PRIVATE_XML,"Exponent"),
    d: xmlParam(PRIVATE_XML,"D"), p: xmlParam(PRIVATE_XML,"P"), q: xmlParam(PRIVATE_XML,"Q"),
    dp: xmlParam(PRIVATE_XML,"DP"), dq: xmlParam(PRIVATE_XML,"DQ"), qi: xmlParam(PRIVATE_XML,"InverseQ") };
  return crypto.createPrivateKey({ key: jwk, format: "jwk" });
}
function signBytes(data) { return crypto.sign("sha256", Buffer.from(data), privateKeyObject()); }
function loadDb() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (parsed && Array.isArray(parsed.licenses)) return parsed;
  } catch {}
  return { licenses: [] };
}
function saveDb(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
}
let db = loadDb();
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!ADMIN_TOKEN || !token || Buffer.byteLength(token) !== Buffer.byteLength(ADMIN_TOKEN) || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_TOKEN))) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}
function licensePayload(name, pc, expiry) {
  const safeName = String(name || "").trim().replace(/[|\r\n]/g, " ").slice(0, 100);
  const safePc = String(pc || "*").trim();
  const safeExpiry = String(expiry || "never").trim();
  if (!safeName) throw new Error("Customer name is required.");
  if (safePc !== "*" && !/^[A-Za-z0-9-]{4,40}$/.test(safePc)) throw new Error("PC ID must be * or a valid machine ID.");
  if (safeExpiry !== "never" && !/^\d{4}-\d{2}-\d{2}$/.test(safeExpiry)) throw new Error("Expiry must be YYYY-MM-DD or never.");
  if (safeExpiry !== "never" && Number.isNaN(Date.parse(safeExpiry + "T00:00:00Z"))) throw new Error("Expiry date is invalid.");
  return Buffer.from(`${safeName}|${safePc}|${safeExpiry}`, "utf8");
}
function idForPayload(payload) { return crypto.createHash("sha256").update(payload).digest("hex"); }
function findLicense(id) { return db.licenses.find(x => x.id === id); }
function issue(name, pc, expiry) {
  const payload = licensePayload(name, pc, expiry);
  const sig = signBytes(payload);
  const key = `FC1.${b64url(payload)}.${b64url(sig)}`;
  const id = idForPayload(payload);
  db.licenses.push({ id, name: String(name).trim(), pc: pc || "*", expiry: expiry || "never", revoked: false, issuedAt: new Date().toISOString() });
  saveDb(db);
  return { key, id, name: String(name).trim(), pc: pc || "*", expiry: expiry || "never" };
}
function setRevoked(id, revoked, details = {}) {
  if (!/^[0-9a-f]{64}$/.test(String(id || ""))) throw new Error("Invalid license ID.");
  let lic = findLicense(id);
  // Supports licenses issued by the previous local generator before migration.
  if (!lic) {
    lic = { id, name: String(details.name || "Imported license").slice(0, 100),
      pc: String(details.pc || "*"), expiry: String(details.expiry || "never"),
      issuedAt: new Date().toISOString(), imported: true };
    db.licenses.push(lic);
  }
  lic.revoked = revoked; lic.updatedAt = new Date().toISOString(); saveDb(db);
  return lic;
}
function signedRevokedList() {
  const ids = db.licenses.filter(x => x.revoked).map(x => x.id).sort();
  const data = ids.join("\n");
  const sig = signBytes(Buffer.from(data, "utf8"));
  return "FCR1\n" + (ids.length ? ids.join("\n") + "\n" : "") + "SIG " + b64url(sig) + "\n";
}
app.get("/health", (_req, res) => res.json({ ok: true, service: "discord-license-service" }));
app.get("/revoked_list.txt", (_req, res) => {
  try { res.type("text/plain").set("Cache-Control", "no-store, max-age=0").send(signedRevokedList()); }
  catch (e) { res.status(503).type("text/plain").send("License service not configured."); }
});
app.post("/api/license/issue", auth, (req, res) => {
  try { const r = issue(req.body.name, req.body.pc || "*", req.body.expiry || "never"); res.json({ ok: true, ...r }); }
  catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.post("/api/license/revoke", auth, (req, res) => {
  try { const lic = setRevoked(req.body.id, true, req.body); res.json({ ok: true, id: lic.id, revoked: true }); }
  catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.post("/api/license/restore", auth, (req, res) => {
  try { const lic = setRevoked(req.body.id, false, req.body); res.json({ ok: true, id: lic.id, revoked: false }); }
  catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});
app.get("/api/license/status/:id", auth, (req, res) => {
  const lic = findLicense(req.params.id);
  if (!lic) return res.status(404).json({ ok: false, error: "License not found" });
  res.json({ ok: true, id: lic.id, name: lic.name, pc: lic.pc, expiry: lic.expiry, revoked: lic.revoked });
});

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const commands = [
  new SlashCommandBuilder().setName("license-issue").setDescription("Generate a license key")
    .addStringOption(o => o.setName("name").setDescription("Customer name").setRequired(true))
    .addStringOption(o => o.setName("pc").setDescription("Machine ID or * for any PC").setRequired(false))
    .addStringOption(o => o.setName("expiry").setDescription("YYYY-MM-DD or never").setRequired(false)),
  new SlashCommandBuilder().setName("license-revoke").setDescription("Revoke a license by its 64-character license ID")
    .addStringOption(o => o.setName("id").setDescription("License ID shown by issue/status").setRequired(true)),
  new SlashCommandBuilder().setName("license-restore").setDescription("Restore a revoked license by ID")
    .addStringOption(o => o.setName("id").setDescription("License ID").setRequired(true)),
  new SlashCommandBuilder().setName("license-status").setDescription("Check license status by ID")
    .addStringOption(o => o.setName("id").setDescription("License ID").setRequired(true))
].map(c => c.setDefaultMemberPermissions(PermissionFlagsBits.Administrator).toJSON());

client.once("ready", async () => {
  console.log(`Discord license bot online as ${client.user.tag}`);
  try {
    if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_GUILD_ID) throw new Error("DISCORD_CLIENT_ID and DISCORD_GUILD_ID are required to register slash commands.");
    const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_BOT_TOKEN);
    await rest.put(Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID, process.env.DISCORD_GUILD_ID), { body: commands });
    console.log("Registered license slash commands in the configured Discord server.");
  } catch (e) { console.error("Slash-command registration failed:", e.message); }
});
client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  if (!interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
    return interaction.reply({ content: "Administrator permission is required.", ephemeral: true });
  }
  try {
    if (interaction.commandName === "license-issue") {
      const r = issue(interaction.options.getString("name"), interaction.options.getString("pc") || "*", interaction.options.getString("expiry") || "never");
      return interaction.reply({ content: `**License created**\nCustomer: ${r.name}\nPC: ${r.pc}\nExpiry: ${r.expiry}\nLicense ID: \`${r.id}\`\nKey: ||\`${r.key}\`||`, ephemeral: true });
    }
    const id = interaction.options.getString("id");
    if (interaction.commandName === "license-revoke") {
      setRevoked(id, true);
      return interaction.reply({ content: `License \`${id}\` revoked. Clients will reject it after their next successful revocation check.`, ephemeral: true });
    }
    if (interaction.commandName === "license-restore") {
      setRevoked(id, false);
      return interaction.reply({ content: `License \`${id}\` restored.`, ephemeral: true });
    }
    if (interaction.commandName === "license-status") {
      const lic = findLicense(id);
      if (!lic) return interaction.reply({ content: "License not found.", ephemeral: true });
      return interaction.reply({ content: `Customer: ${lic.name}\nPC: ${lic.pc}\nExpiry: ${lic.expiry}\nStatus: **${lic.revoked ? "REVOKED" : "ACTIVE"}**`, ephemeral: true });
    }
  } catch (e) {
    const msg = String(e.message || e).slice(0, 1500);
    if (interaction.deferred || interaction.replied) return interaction.followUp({ content: "Error: " + msg, ephemeral: true });
    return interaction.reply({ content: "Error: " + msg, ephemeral: true });
  }
});

app.listen(PORT, "0.0.0.0", () => console.log(`License HTTP service listening on ${PORT}`));
client.login(process.env.DISCORD_BOT_TOKEN).catch(err => {
  console.error("Discord login failed:", err.message);
  process.exit(1);
});
