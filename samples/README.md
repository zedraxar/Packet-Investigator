# Packet capture samples

Packet captures should normally never be committed. They can expose
credentials, personal information, internal network details, and sensitive
payload data.

Any capture committed to this repository must be:

- Synthetic
- Sanitized
- Legally authorized
- Free of credentials or sensitive payload data

Store local captures under `samples/private/`; its contents are ignored by Git.
