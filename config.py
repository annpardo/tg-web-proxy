PORT = 8080

# name -> secret (32 hex chars)
# WEB mode also accepts dd + 32 hex chars (34 total) for random padding.
USERS = {
    "tg":  "00000000000000000000000000000001",
    # "tg2": "0123456789abcdef0123456789abcdef",
}

MODES = {
    # Classic mode, easy to detect
    "classic": False,

    # Makes the proxy harder to detect
    # Can be incompatible with very old clients
    "secure": False,

    # Makes the proxy even more hard to detect
    # Can be incompatible with old clients
    "tls": True,

    # WEB mode (enable on its own: set classic/secure/tls above to False)
    "web": False
}

# Only used in WEB mode. Your Cloudflare proxied hostname, without scheme/port.
WEB_DOMAIN = "mtp.tincg.de5.net"

# The domain for TLS mode, bad clients are proxied there
# Use random existing domain, proxy checks it on start
# TLS_DOMAIN = "www.google.com"

# Tag for advertising, obtainable from @MTProxybot
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"
