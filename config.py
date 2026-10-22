"""Settings, overridable from the environment so a hosted deploy needs no rebuild.

InstaCloud routes :8080 to the app and waits for it to listen there, so 8080 is
the default. On a VPS where you want the classic 443, set PORT=443.
"""
import os


def _flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


PORT = int(os.environ.get("PORT", "8080"))

# name -> secret (32 hex chars)
# WEB mode also accepts dd + 32 hex chars (34 total) for random padding.
USERS = {
    "tg": os.environ.get("TG_SECRET", "00000000000000000000000000000001"),
}

# WEB_MODE=1 moves the public listener from classic/tls MTProto to the
# HTTPS + WebSocket carrier. Turn it on when TLS is terminated in front of the
# app (InstaCloud http endpoint); leave it off for a raw tcp port or for
# Cloudflare Full, where the proxy speaks TLS itself.
_WEB = _flag("WEB_MODE", False)

MODES = {
    # Classic mode, easy to detect
    "classic": False,

    # Makes the proxy harder to detect
    # Can be incompatible with very old clients
    "secure": False,

    # Makes the proxy even more hard to detect
    # Can be incompatible with old clients
    "tls": not _WEB,

    # WEB mode (enable on its own: set classic/secure/tls above to False)
    "web": _WEB,
}

# Only used in WEB mode: the exact Host clients use, without scheme or port.
WEB_DOMAIN = os.environ.get("WEB_DOMAIN", "")

# Only used in WEB mode. True: terminate TLS here with a generated self-signed
# cert (Cloudflare "Full"). False: plain HTTP/WS, TLS terminated by the platform.
WEB_TLS = _flag("WEB_TLS", True)

# Optional: the address printed in tg://proxy links. Empty means "detect it",
# which inside a container prints the wrong thing, so set it when you care.
MY_DOMAIN = os.environ.get("MY_DOMAIN", "")

# The domain for TLS mode, bad clients are proxied there
# Use random existing domain, proxy checks it on start
# TLS_DOMAIN = "www.google.com"

# Tag for advertising, obtainable from @MTProxybot
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"
