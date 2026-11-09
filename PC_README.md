# Run the same Discord vault on your Windows PC

This repository now includes a local launcher and a separate RAM-disk leech.

## 1. Local PC vault interface

1. Download or clone this repository to your PC.
2. Copy `pc_leech_config.example.json` to `pc_leech_config.json`.
3. Fill in your own Discord bot token, the existing vault channel ID, and the exact existing vault password. Keep this file private; it is ignored by Git.
4. Double-click `run_pc_vault.bat`.
5. Open `http://127.0.0.1:8787` in your browser.

This starts the existing phone vault application locally. It uses the same Discord channel, encryption derivation, and file format. It does not create a second vault or copy your files.

## 2. PC Leech (RAM disk only)

The separate `pc_leech.py` app downloads with aria2 into a RAM disk folder, then encrypts and uploads files into the same Discord vault. It deletes the temporary job folder after the job ends.

**Important:** Windows does not provide a normal RAM drive by default. Create a RAM disk using software already approved on your PC, then set `PC_RAM_DIR` in `pc_leech_config.json` to that drive's folder (the example uses `R:\\`). The app checks that the folder exists and refuses to fall back to the ordinary disk. RAM is volatile: downloads in progress are lost if the PC shuts down or restarts. Make sure the RAM disk has enough free space for the entire download.

Install aria2 and ensure `aria2c.exe` is available in PATH. Then double-click `run_pc_leech.bat` and open `http://127.0.0.1:8790`.

The PC Leech config needs:
- `DISCORD_TOKEN`: your bot token (private)
- `DISCORD_CHANNEL`: the same channel used by the existing vault
- `VAULT_PASSWORD`: the exact existing vault password
- `PC_LEECH_KEY`: a private local access key of at least 12 characters
- `PC_RAM_DIR`: a folder on the RAM disk

Do not paste tokens or passwords into chat or commit `pc_leech_config.json` to GitHub.

## Notes

- The local vault and PC Leech listen only on `127.0.0.1`; they are not exposed to the public internet.
- Discord's upload limits, rate limits, and your network speed still apply.
- RAM capacity limits the maximum in-progress download size. This does not increase Discord's storage allowance.
- The existing Render service remains separate and unchanged by running the PC apps.
