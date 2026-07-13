"""Post the estate alert envelope to atlas-notify from GitHub Actions.

Same fixed envelope Workers send over the ATLAS_NOTIFY service binding
({source: "alert", level, title, message, fields}), delivered over the
public /notify route with the shared Bearer NOTIFY_TOKEN instead of a
binding, because an Actions runner is outside Cloudflare's network and
service bindings do not exist for it. The public-hostname 522 problem
only bites Worker-to-Worker calls; runner-to-Worker over the public
route is the normal case.

Routing through atlas-notify rather than a direct Discord webhook is
deliberate: the weekly summaries then also land in the /notify/recent
ring buffer, which is exactly the feed the Home Assistant dashboard
and the Lab Failure log read.
"""

import json
import os
import urllib.error
import urllib.request

NOTIFY_URL = "https://api.atlas-systems.uk/notify"
MESSAGE_LIMIT = 1800


def post_summary(level, title, message, fields=None):
    """Deliver one envelope. Never raises; returns True on 2xx.

    The summary is the product of a job that already printed its full
    findings to the Actions log, so a failed post degrades to 'read the
    log' rather than taking the job down with it.
    """
    token = os.environ.get("NOTIFY_TOKEN", "").strip()
    if not token:
        print("notify: NOTIFY_TOKEN not set; summary printed above only")
        return False

    body = {
        "source": "alert",
        "level": level,
        "title": title,
        "message": message[:MESSAGE_LIMIT],
        "fields": fields or {},
    }
    signal_class = os.environ.get("NOTIFY_SIGNAL_CLASS", "").strip()
    if signal_class:
        body["signal_class"] = signal_class

    req = urllib.request.Request(
        NOTIFY_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "atlas-dep-audit (+https://atlas-systems.uk)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            print(f"notify: delivered (http {res.status})")
            return 200 <= res.status < 300
    except urllib.error.HTTPError as err:
        print(f"notify: rejected (http {err.code})")
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        print(f"notify: unreachable ({err.__class__.__name__})")
        return False
