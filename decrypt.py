#!/usr/bin/env python3
"""
darktunnel_decrypt.py — DarkTunnel .dark config decryptor (standalone, no server deps)

Reimplements the full DarkTunnel config encryption chain:

  1. file text      : darktunnel://<base64url JSON>
  2. JSON.encryptedLockedConfig (base64url)
       -> AES-256-CFB, key = KEY_256, iv = IV  -> msgpack {LockedAppConfig, EncryptedLockedConfig}
  3. EncryptedLockedConfig (raw bytes)
       -> AES-192-CFB, key = KEY_192, iv = IV   -> msgpack {InjectConfig, SshConfig, V2RayConfig}
  4. every sub-field (EncryptedConfig, EncryptedPayload, EncryptedMode, ...)
       -> AES-192-CFB, key = KEY_192, iv = IV, per-field chaining (iv reset each field)

Usage:
    python3 darktunnel_decrypt.py <file.dark>
    python3 darktunnel_decrypt.py --raw '<darktunnel://...>'
    cat file.dark | python3 darktunnel_decrypt.py -
    python3 darktunnel_decrypt.py <file.dark> --json out.json

Requires: pycryptodome  (pip install pycryptodome)
          msgpack       (optional — bundled fallback parser included)
"""

import argparse
import base64
import json
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write("missing pycryptodome ->  pip install pycryptodome\n")
    raise

KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV = bytes.fromhex("232e39185523184a5723586242200e05")

PREFIX = "darktunnel://"

try:
    import msgpack as _msgpack
except ImportError:
    _msgpack = None


# ---------------------------------------------------------------- base64url

def b64url_decode(s: str) -> bytes:
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- msgpack (fallback)

class _FallbackUnpacker:
    """Minimal msgpack reader — covers types used by DarkTunnel configs."""

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def _take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ValueError("msgpack: truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def _u8(self):
        return self._take(1)[0]

    def _u16(self):
        return int.from_bytes(self._take(2), "big")

    def _u32(self):
        return int.from_bytes(self._take(4), "big")

    def _u64(self):
        return int.from_bytes(self._take(8), "big")

    def _str(self, n: int) -> str:
        return self._take(n).decode("utf-8", "replace")

    def read(self):
        b = self._u8()
        if b <= 0x7F:                      # positive fixint
            return b
        if b >= 0xE0:                      # negative fixint
            return b - 0x100
        if 0x80 <= b <= 0x8F:              # fixmap
            return self._map(b & 0x0F)
        if 0x90 <= b <= 0x9F:              # fixarray
            return self._array(b & 0x0F)
        if 0xA0 <= b <= 0xBF:              # fixstr
            return self._str(b & 0x1F)
        if b == 0xC0:
            return None
        if b == 0xC2:
            return False
        if b == 0xC3:
            return True
        if b == 0xC4:
            return self._take(self._u8())          # bin8
        if b == 0xC5:
            return self._take(self._u16())         # bin16
        if b == 0xC6:
            return self._take(self._u32())         # bin32
        if b == 0xCA:
            import struct
            return struct.unpack(">f", self._take(4))[0]
        if b == 0xCB:
            import struct
            return struct.unpack(">d", self._take(8))[0]
        if b == 0xCC:
            return self._u8()
        if b == 0xCD:
            return self._u16()
        if b == 0xCE:
            return self._u32()
        if b == 0xCF:
            return self._u64()
        if b == 0xD0:
            return self._u8() - 0x100
        if b == 0xD1:
            return self._u16() - 0x10000
        if b == 0xD2:
            return self._u32() - 0x100000000
        if b == 0xD3:
            return self._u64() - 0x10000000000000000
        if b == 0xD9:
            return self._str(self._u8())           # str8
        if b == 0xDA:
            return self._str(self._u16())          # str16
        if b == 0xDB:
            return self._str(self._u32())          # str32
        if b == 0xDC:
            return self._array(self._u16())        # array16
        if b == 0xDD:
            return self._array(self._u32())        # array32
        if b == 0xDE:
            return self._map(self._u16())          # map16
        if b == 0xDF:
            return self._map(self._u32())          # map32
        raise ValueError(f"msgpack: unsupported byte 0x{b:02x} at {self.i - 1}")

    def _map(self, n):
        out = {}
        for _ in range(n):
            k = self.read()
            if isinstance(k, bytes):
                k = k.decode("utf-8", "replace")
            out[k] = self.read()
        return out

    def _array(self, n):
        return [self.read() for _ in range(n)]


def mp_unpack(data: bytes):
    if _msgpack is not None:
        return _msgpack.unpackb(data, raw=False, strict_map_key=False)
    return _FallbackUnpacker(data).read()


# ---------------------------------------------------------------- AES-CFB (segmented)

def cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CFB full-segment: ciphertext blocks chain (prev = ciphertext block)."""
    ecb = AES.new(key, AES.MODE_ECB)
    out = bytearray(len(data))
    prev = iv
    for i in range(0, len(data), 16):
        ks = ecb.encrypt(prev)
        chunk = data[i:i + 16]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
        prev = chunk
    return bytes(out)


def cfb_field_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Per-field CFB: each field restarts from the master IV."""
    return cfb_decrypt(key, iv, data)


# ---------------------------------------------------------------- chain

def decrypt_dark(raw_text: str) -> dict:
    text = raw_text.strip()
    if text.startswith(PREFIX):
        text = text[len(PREFIX):]
    if not text.startswith("eyJ"):
        # maybe whole file is just the base64url payload, or a JSON blob
        try:
            obj = json.loads(text)
            if "encryptedLockedConfig" in obj:
                enc = obj["encryptedLockedConfig"]
            else:
                raise ValueError
        except (ValueError, json.JSONDecodeError):
            enc = text
    else:
        enc = None

    if enc is None:
        outer_json = json.loads(b64url_decode(text))
        enc = outer_json["encryptedLockedConfig"]
        outer_meta = outer_json
    else:
        outer_meta = {"type": "inline", "name": None}

    outer_ct = b64url_decode(enc)

    # layer 1: AES-256-CFB
    layer1 = cfb_decrypt(KEY_256, IV, outer_ct)
    m1 = mp_unpack(layer1)

    # layer 2: AES-192-CFB
    layer2 = cfb_decrypt(KEY_192, IV, m1["EncryptedLockedConfig"])
    m2 = mp_unpack(layer2)

    # layer 3: per-field AES-192-CFB
    def fields_out(section: dict) -> dict:
        out = {}
        for k, v in section.items():
            if isinstance(v, bytes):
                if k.startswith("Encrypted") and v:
                    dec = cfb_field_decrypt(KEY_192, IV, v)
                    # prefer utf-8 when it decodes cleanly, else keep bytes hex
                    try:
                        s = dec.decode("utf-8")
                        if all(c.isprintable() or c in "\r\n\t" for c in s):
                            out[k.replace("Encrypted", "", 1) if k != "EncryptedConfig" else "Config"] = s
                            continue
                    except UnicodeDecodeError:
                        pass
                    out[k.replace("Encrypted", "", 1) if k != "EncryptedConfig" else "Config"] = dec.hex()
                elif k.startswith("Encrypted"):
                    out[k.replace("Encrypted", "", 1)] = v
                else:
                    out[k] = v
            else:
                out[k] = v
        return out

    result = {
        "meta": {
            "type": outer_meta.get("type"),
            "name": outer_meta.get("name"),
        },
        "LockedAppConfig": m1.get("LockedAppConfig", {}),
        "InjectConfig": fields_out(m2.get("InjectConfig", {})),
        "SshConfig": fields_out(m2.get("SshConfig", {})),
        "V2RayConfig": fields_out(m2.get("V2RayConfig", {})),
    }

    # parse the v2ray JSON text if present (template vars like $PORT break strict JSON)
    cfg_text = result["V2RayConfig"].get("Config")
    if isinstance(cfg_text, str) and cfg_text.lstrip().startswith("{"):
        try:
            result["V2RayConfig"]["Config"] = json.loads(cfg_text)
        except json.JSONDecodeError:
            sanitized = _sanitize_template_vars(cfg_text)
            try:
                parsed = json.loads(sanitized)
                result["V2RayConfig"]["Config"] = parsed
                result["V2RayConfig"]["TemplateVars"] = True
            except json.JSONDecodeError:
                pass  # keep raw text
    return result


def _sanitize_template_vars(text: str) -> str:
    """Quote bare $VARS so DarkTunnel's template placeholders parse as JSON."""
    import re
    return re.sub(r'(?<=[:\[,])(\$[A-Z_0-9]+)(?=[,\]\}])', r'"\1"', text)


def build_vless_uri(v2ray: dict) -> str:
    """Build a shareable vless:// URI from the decrypted v2ray config (best-effort)."""
    if not isinstance(v2ray, dict):
        return None
    try:
        outb = v2ray["outbounds"][0]
        settings = outb["settings"]["vnext"][0]
        user = settings["users"][0]
        ss = outb.get("streamSettings", {})
        host = settings["address"]
        port = settings["port"]
        uuid = user["id"]
    except (KeyError, IndexError, TypeError):
        return None

    params = []
    params.append("encryption=" + user.get("encryption", "none"))
    net = ss.get("network")
    if net:
        params.append("type=" + net)
    if net == "ws":
        ws = ss.get("wsSettings", {})
        path = ws.get("path")
        if path:
            params.append("path=" + path.replace("?", "%3F"))
        headers = ws.get("headers", {})
        if "Host" in headers:
            params.append("host=" + headers["Host"])
    sec = ss.get("security")
    if sec and sec != "none":
        params.append("security=" + sec)
        tls = ss.get("tlsSettings", {})
        if tls.get("serverName"):
            params.append("sni=" + tls["serverName"])
    label = v2ray.get("_label") or "DarkTunnel"
    from urllib.parse import quote
    return f"vless://{uuid}@{host}:{port}?{'&'.join(params)}#{quote(str(label), safe='')}"


# ---------------------------------------------------------------- io / cli

def read_input(args) -> str:
    if args.raw:
        return args.raw
    if args.input == "-":
        return sys.stdin.read()
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description="Decrypt DarkTunnel .dark configs")
    ap.add_argument("input", nargs="?", help=".dark file path, or '-' for stdin")
    ap.add_argument("--raw", help="inline darktunnel:// payload")
    ap.add_argument("--json", help="write decrypted JSON to this path")
    ap.add_argument("--quiet", action="store_true", help="only print vless:// URI")
    args = ap.parse_args()

    if not args.input and not args.raw:
        ap.error("give a .dark file, '-' for stdin, or --raw payload")

    text = read_input(args)
    result = decrypt_dark(text)

    uri = None
    vc = result.get("V2RayConfig", {}).get("Config")
    if isinstance(vc, dict):
        if result["meta"].get("name"):
            vc["_label"] = result["meta"]["name"]
        uri = build_vless_uri(vc)

    if args.json:
        out = json.loads(json.dumps(result, default=str))
        cfg = out.get("V2RayConfig", {}).get("Config")
        if isinstance(cfg, dict):
            cfg.pop("_label", None)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False, default=str)
        if not args.quiet:
            sys.stderr.write(f"written: {args.json}\n")

    if args.quiet:
        if uri:
            print(uri)
        return

    print("=" * 60)
    print("DarkTunnel config — decrypted")
    print("=" * 60)
    meta = result["meta"]
    if meta.get("name"):
        print(f"name:      {meta['name']}")
    if meta.get("type"):
        print(f"type:      {meta['type']}")

    lac = result.get("LockedAppConfig", {})
    if lac:
        print("\n-- LockedAppConfig --")
        for k in ("VersionCode", "VersionName", "TunnelType", "IsSshLocked", "ExpiredAtTimestamp"):
            if k in lac:
                v = lac[k]
                if isinstance(v, bytes):
                    v = v.decode("utf-8", "replace")
                print(f"{k}: {v}")
        if "Password" in lac:
            pw = lac["Password"]
            print(f"Password: {pw.hex() if isinstance(pw, bytes) else pw}")

    for sect in ("InjectConfig", "SshConfig", "V2RayConfig"):
        d = result.get(sect, {})
        if not d:
            continue
        print(f"\n-- {sect} --")
        for k, v in d.items():
            if k == "Config" and isinstance(v, dict):
                continue
            if isinstance(v, bytes):
                v = v.hex()
            print(f"{k}: {v}")

    if isinstance(vc, dict):
        print("\n-- V2Ray config (decrypted) --")
        vc_print = {k: v for k, v in vc.items() if k != "_label"}
        print(json.dumps(vc_print, indent=2, ensure_ascii=False))
        outb = vc.get("outbounds", [{}])[0]
        vnext = outb.get("settings", {}).get("vnext", [{}])[0]
        if vnext:
            print(f"\naddress: {vnext.get('address')}")
            print(f"port:    {vnext.get('port')}")
            users = vnext.get("users", [{}])
            if users:
                print(f"uuid:    {users[0].get('id')}")

    if uri:
        print("\n" + "=" * 60)
        print("share URI:")
        print(uri)


if __name__ == "__main__":
    main()
