# darktunnel-decrypt

Decrypt DarkTunnel `.dark` config files offline.

No server, no login, no telemetry. One Python file, runs locally.

## why

DarkTunnel configs are encrypted in three layers before they leave the app.
If you want to see what's actually inside a config someone shared with you —
the server, the UUID, the WS path, the inject payload — you need to decrypt it
first. This does that, offline.

## what it gives you

```
$ python3 decrypt.py JIO_4G.dark
============================================================
DarkTunnel config — decrypted
============================================================
name:      JIO 4G NO SPEED CAP
type:      VLESS

-- LockedAppConfig --
VersionCode: 32
VersionName: 1.0.26
TunnelType: VLESS

-- InjectConfig --
Mode: DIRECT
ProxyHost: localhost
ProxyPort: 8080
Payload: [method] [host_port] [protocol][crlf]Host: [host]...

-- V2RayConfig --
address: fota.slv.sit.jiophone.net
port:    80
uuid:    @coldpllay

============================================================
share URI:
vless://@coldpllay@fota.slv.sit.jiophone.net:80?encryption=none&type=ws&path=/lecture-assets&host=science.gixservices.com#...
```

## usage

```bash
pip install pycryptodome

python3 decrypt.py config.dark              # full dump
python3 decrypt.py config.dark --quiet      # just the share URI
python3 decrypt.py config.dark --json o.json
cat config.dark | python3 decrypt.py -      # from stdin
python3 decrypt.py --raw 'darktunnel://...' # inline payload
```

`msgpack` is optional. If it's not installed the script falls back to its own
parser — either way it works.

## what's inside the box

Three layers, all reversed:

| layer | cipher | key | output |
|---|---|---|---|
| 1 | AES-256-CFB | `KEY_256` | msgpack `{LockedAppConfig, EncryptedLockedConfig}` |
| 2 | AES-192-CFB | `KEY_192` | msgpack `{InjectConfig, SshConfig, V2RayConfig}` |
| 3 | AES-192-CFB (per-field) | `KEY_192` | plaintext fields |

IV is the same across all three. Keys and IV are the ones used by DarkTunnel
1.0.26 (versionCode 32) — they're in the script.

The tunnel type (VLESS / VMess / Trojan / SSH) doesn't matter here. That only
changes the JSON payload inside layer 3. The envelope is always the same, so
any `.dark` file exported from the app will open.

## limits

- If DarkTunnel updates its keys in a future release, this breaks until the new
  ones are pulled out.
- `Password` in `LockedAppConfig` comes out as a SHA-256 hash with a salt.
  It's stored hashed on purpose — there's nothing to recover there.
- Only handles files made by the DarkTunnel app. A random file named `.dark`
  from something else won't parse.

