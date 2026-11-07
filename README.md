# Vault Phone

A phone-friendly web interface for your encrypted Discord vault. The Flask service runs behind Render's HTTPS proxy; it does not store uploaded vault contents on local disk.

## Render settings
- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `python phone_plus.py`
- Plan: Free
- Environment variables: `DISCORD_TOKEN`, `DISCORD_CHANNEL`

Set both values privately in Render's Environment page. Do not put credentials in source files or GitHub.

The vault password is entered in the app and is used to unlock the existing encrypted vault.
