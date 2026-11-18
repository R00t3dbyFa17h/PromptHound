"""Direct prompt-injection prober for AI/LLM HTTP endpoints.

You describe the request shape of a target's AI feature once (URL, method, a body
or query template containing the literal placeholder ``{{PAYLOAD}}``), and the
prober substitutes each injection payload, sends it, and flags any response whose
body contains the payload's unique **canary** — strong evidence the injected
instruction was ingested and/or followed.

It is deliberately generic: AI endpoints differ wildly, so you supply the request
template and the prober handles iteration, canary detection, pacing, and output.

AUTHORIZED USE ONLY. Only point this at AI features that are in scope for a
program/engagement you are authorized to test.
"""
from __future__ import annotations

import json
import time

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

PLACEHOLDER = "{{PAYLOAD}}"


class ProbeResult:
    def __init__(self, category, name, canary, status, hit, snippet):
        self.category = category
        self.name = name
        self.canary = canary
        self.status = status
        self.hit = hit          # canary found in response => likely ingested/followed
        self.snippet = snippet

    def to_dict(self):
        return self.__dict__


def _fill(obj, payload):
    """Recursively substitute the placeholder in strings within headers/body."""
    if isinstance(obj, str):
        return obj.replace(PLACEHOLDER, payload)
    if isinstance(obj, dict):
        return {k: _fill(v, payload) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, payload) for v in obj]
    return obj


def probe(url, payloads, method="POST", headers=None, body=None, params=None,
          json_body=None, response_path=None, delay=0.5, timeout=20,
          proxy=None, verify=True, verbose=False):
    """Run a batch of injection payloads against one endpoint.

    payloads: list of dicts from payloads.build() (need 'text' and 'canary').
    body / json_body / params: the request template; put {{PAYLOAD}} where the
        user-controlled prompt/content goes.
    response_path: optional dotted path (e.g. 'choices.0.message.content') to pull
        the model's text out of a JSON response before canary matching.
    Returns list[ProbeResult].
    """
    if requests is None:
        raise RuntimeError("the 'requests' package is required for probing")
    sess = requests.Session()
    if proxy:
        sess.proxies.update({"http": proxy, "https": proxy})
    results = []
    for p in payloads:
        payload, canary = p["text"], p["canary"]
        kw = {"timeout": timeout, "verify": verify}
        kw["headers"] = _fill(headers or {}, payload)
        if params is not None:
            kw["params"] = _fill(params, payload)
        if json_body is not None:
            kw["json"] = _fill(json_body, payload)
        elif body is not None:
            kw["data"] = _fill(body, payload)
        try:
            r = sess.request(method, url, **kw)
            text = _extract(r, response_path)
            hit = canary in text
            results.append(ProbeResult(p["category"], p["name"], canary,
                                       r.status_code, hit, _snippet(text, canary)))
            if verbose:
                flag = "HIT " if hit else "    "
                print(f"[{flag}] {p['category']}/{p['name']:18s} {r.status_code} canary={canary}")
        except Exception as e:  # noqa
            results.append(ProbeResult(p["category"], p["name"], canary, None, False, f"ERROR: {e}"))
            if verbose:
                print(f"[ERR ] {p['category']}/{p['name']}: {e}")
        time.sleep(delay)
    return results


def _extract(resp, response_path):
    if not response_path:
        return resp.text or ""
    try:
        data = resp.json()
    except Exception:
        return resp.text or ""
    cur = data
    for part in response_path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur.get(part, "")
        else:
            return str(cur)
    return cur if isinstance(cur, str) else json.dumps(cur)


def _snippet(text, canary, pad=80):
    i = text.find(canary)
    if i < 0:
        return (text or "")[:160].replace("\n", " ")
    return text[max(0, i - pad):i + len(canary) + pad].replace("\n", " ")
