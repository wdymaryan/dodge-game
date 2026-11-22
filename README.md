# Dodge

An endless 2D platformer with a level editor, live player queue, leaderboards, and community levels, hosted on Cloudflare Workers + D1.

## Setup on Cloudflare
1. Connect this GitHub repository in **Workers & Pages** > **Create** > **Import a repository**.
2. Create a D1 database named `dodge-db` under **Storage & Databases** > **D1 SQL database**.
3. In your Worker's **Settings** > **Bindings**, add a **D1 database** binding named `DB` pointing to `dodge-db`.
