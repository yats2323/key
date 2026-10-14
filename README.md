# Discord License Bot (starter)

This service replaces GitHub as the revocation-list host and adds Discord slash commands for license management. It is a deployable starter, **not yet connected to your PowerShell GUI**.

## What it does

- `/license-issue name:<customer> pc:<machine-id-or-*> expiry:<YYYY-MM-DD-or-never>` generates an `FC1` key signed with the existing RSA private key.
- `/license-revoke id:<64-character-license-id>` revokes a license.
- `/license-restore id:<id>` restores a license.
- `/license-status id:<id>` checks the record.
- `GET /revoked_list.txt` serves a signed `FCR1` list compatible with the current VideoClipper validator.
- Authenticated JSON API routes are available for connecting the PowerShell license-generator GUI later.

All Discord commands require Discord Administrator permission. Replies containing keys are ephemeral.

## Critical security notes

1. The private RSA signing key and `ADMIN_API_TOKEN` must be configured as server environment variables. Never put them in the VideoClipper customer script, a public repository, or a Discord channel.
2. The current uploaded generator contains an RSA private key and a Discord webhook URL. Treat the webhook URL as exposed: delete/recreate it in Discord before using it again. Keep the private signing key only on your private machine or move it to this service after verifying the matching public key.
3. The current bot's JSON database must live on persistent storage. On hosts with ephemeral filesystems, set `DATA_FILE` to a mounted persistent disk path, or records can disappear on redeploy.
4. Set a long random `ADMIN_API_TOKEN`. Do not expose the administrative API token in the VideoClipper client app.
5. The current client checks a signed revocation list. The service signs with the same RSA keypair as the current key format; confirm the public key in the app matches before deployment.
6. For production, use HTTPS, rate limits, backups, and a proper persistent database. Protect `/api/license/*` with the admin token and keep the service updated.

## Render deployment (recommended)

This project includes `render.yaml`. Create a **private Git repository** for the contents of this folder only (do not put the seller-only PowerShell generator in it), push the bot files, then in Render choose **New > Blueprint** and connect that repository. The blueprint creates a paid Starter web service with a 1 GB persistent disk at `/var/data`; persistent storage is required because Render's ordinary filesystem is ephemeral.

Set the following secrets in Render when prompted:

- `DISCORD_BOT_TOKEN`: bot token from Discord Developer Portal > Bot. If the token has ever been shared, reset it first.
- `DISCORD_GUILD_ID`: your Discord server ID (enable Developer Mode, right-click the server icon/name, Copy Server ID).
- `ADMIN_API_TOKEN`: a long random secret, for example generate one locally with PowerShell: `[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))`.
- `LICENSE_PRIVATE_XML`: the complete existing `<RSAKeyValue>...</RSAKeyValue>` private XML from the seller-only generator. Do not add quotes around it. Store only as a Render secret.

The blueprint pre-fills `DISCORD_CLIENT_ID` from the application ID you supplied. After deploy, open the Render service URL and check `/health`; then check `/revoked_list.txt` returns text beginning with `FCR1`.

## Setup (manual alternative)

1. Create a Discord application and bot at https://discord.com/developers/applications.
2. Invite the bot to your server with `bot` and `applications.commands` scopes. It needs no message-content intent.
3. Deploy this Node.js project to a host that stays online and provides HTTPS and persistent storage (for example, a VPS or a hosting service with a persistent disk).
4. Configure environment variables from `.env.example`.
5. Set `LICENSE_PRIVATE_XML` to the exact existing RSA XML private key from your seller-only generator. Store it as a host secret, not in source code.
6. Run `npm install` and `npm start`; the bot registers its guild slash commands when it connects.
7. Visit `/health` and `/revoked_list.txt` on your HTTPS host.
8. Update the VideoClipper script's `$script:RevokeUrl` to `https://YOUR-HOST/revoked_list.txt`.

## API

All admin routes require `Authorization: Bearer <ADMIN_API_TOKEN>`.

- `POST /api/license/issue` JSON `{ "name": "Customer", "pc": "*", "expiry": "never" }`
- `POST /api/license/revoke` JSON `{ "id": "<license-id>" }`
- `POST /api/license/restore` JSON `{ "id": "<license-id>" }`
- `GET /api/license/status/<id>`

**Important:** The current PowerShell generator still issues keys locally and publishes to GitHub. This starter adds a Discord-managed service, but the generator GUI must be adapted to call the API before GitHub is fully removed. Test revocation on a disposable test key first.


## Connect the PowerShell scripts

Use the separate modified PowerShell files supplied in this conversation. In the seller-only generator, replace `https://YOUR-RENDER-SERVICE.onrender.com` with the real Render URL and set `$licenseApiToken` to the same value as Render's `ADMIN_API_TOKEN`. Keep this generator private because it contains the RSA private key and the API token. In VideoClipper, replace `https://YOUR-RENDER-SERVICE.onrender.com/revoked_list.txt` with the real Render URL. The public app downloads only the signed revocation list; it must never contain the admin API token.

The generator's issue/revoke/restore buttons call the service and report failure if the service does not confirm. The service also supports old license IDs when you revoke/restore an existing key from the local history. Test with a disposable key first.
