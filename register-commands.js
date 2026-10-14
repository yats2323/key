const { REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require("discord.js");
const commands = [
  new SlashCommandBuilder().setName("license-issue").setDescription("Generate a license key")
    .addStringOption(o => o.setName("name").setDescription("Customer name").setRequired(true))
    .addStringOption(o => o.setName("pc").setDescription("Machine ID or * for any PC").setRequired(false))
    .addStringOption(o => o.setName("expiry").setDescription("YYYY-MM-DD or never").setRequired(false)),
  new SlashCommandBuilder().setName("license-revoke").setDescription("Revoke a license by its 64-character license ID")
    .addStringOption(o => o.setName("id").setDescription("License ID").setRequired(true)),
  new SlashCommandBuilder().setName("license-restore").setDescription("Restore a revoked license by ID")
    .addStringOption(o => o.setName("id").setDescription("License ID").setRequired(true)),
  new SlashCommandBuilder().setName("license-status").setDescription("Check license status by ID")
    .addStringOption(o => o.setName("id").setDescription("License ID").setRequired(true))
].map(c => c.setDefaultMemberPermissions(PermissionFlagsBits.Administrator).toJSON());
(async () => {
  const { DISCORD_BOT_TOKEN, DISCORD_CLIENT_ID, DISCORD_GUILD_ID } = process.env;
  if (!DISCORD_BOT_TOKEN || !DISCORD_CLIENT_ID || !DISCORD_GUILD_ID) throw new Error("Set DISCORD_BOT_TOKEN, DISCORD_CLIENT_ID, and DISCORD_GUILD_ID.");
  const rest = new REST({ version: "10" }).setToken(DISCORD_BOT_TOKEN);
  await rest.put(Routes.applicationGuildCommands(DISCORD_CLIENT_ID, DISCORD_GUILD_ID), { body: commands });
  console.log("Registered guild license commands.");
})().catch(e => { console.error(e); process.exit(1); });
