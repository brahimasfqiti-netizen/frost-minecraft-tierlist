# FROST Minecraft PvP Tierlist

Original Minecraft PvP rankings site with a private staff panel, player test applications, and persistent local data. The project uses only Node.js built-in modules; no package installation is required.

## Run locally

1. Install Node.js 20 or later.
2. From this folder, run `node server.mjs`.
3. Open `http://127.0.0.1:4173`.
4. Open `/admin.html`. On the first run, the server prints a one-time owner setup token in the terminal. If the server has already been started, the token is in `private/setup-token.txt`.
5. Enter that token, choose an owner username, and create a unique password with at least 12 characters.
6. In **Staff Accounts**, add admins and testers with separate strong passwords.

The one-time token and local account database live under `private/`, which is excluded by `.gitignore`. Passwords are stored as salted scrypt hashes. Staff sessions use HTTP-only, same-site cookies and expire after eight hours. Login, test applications, and public list suggestions are rate limited.

## Roles

- **Owner:** review test applications, add or remove public player rankings, and create staff accounts.
- **Admin:** review applications and manage public player rankings.
- **Tester:** review test applications and assign a tier when approving a player.
- **Community:** suggest players to add, tier updates, or player removals from the public page. Every suggestion must be reviewed by staff before it changes the rankings.

The public leaderboard supports Sword, Axe, Crystal, UHC, Pot, NethPot, SMP, DiaPot, Mace, and Creeper. Tier order is HTX, HT1/LT1, HT2/LT2, HT3/LT3, HT4/LT4, and HT5/LT5.

## Public change log

Approved ranking additions, tier changes, and removals are recorded in the public field log. The leaderboard and log refresh automatically every 15 seconds while the page is open. The log shows the player, mode, old and new tier when relevant, timestamp, and reviewing staff account. Community suggestions stay private to staff until approval.

## Deployment

Run behind a hosting provider that supports persistent Node.js processes and persistent disk. Configure HTTPS at the reverse proxy, set `NODE_ENV=production`, and choose `PORT` and `HOST` using the host's environment settings. Keep `private/` out of public static-file roots and backups that are shared publicly. The default bind address is loopback-only for local development.

The configured partner link is `https://achost.site/landing.html`. Replace it in `public/index.html` if your partner page changes.
