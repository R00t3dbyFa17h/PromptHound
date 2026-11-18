"""PromptHound command-line interface.

Subcommands:
  gen        craft a hidden-payload document (PDF/HTML/SVG/TXT) for indirect injection
  probe      fire direct-injection payloads at an AI HTTP endpoint and detect canaries
  payloads   list / render the injection payload library
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import payloads as P
from . import docgen, prober

BANNER = r"""
  ___                _   _                 _
 | _ \_ ____ _ __  __| |_| |_ ___ _  _ _ _ __| |
 |  _/ '_/ _ \ '  \/ _` |  _| ' \/ _ \ || | ' \/ _` |
 |_| |_| \___/_|_|_\__,_|\__|_||_\___/\_,_|_||_\__,_|
   indirect + direct prompt-injection harness  (authorized testing only)
"""


def _banner():
    print(BANNER)


def cmd_payloads(args):
    sample = P.new_canary()
    for cat, name, tmpl in P.select(args.category):
        if args.render:
            print(f"### {cat}/{name}\n{P.render(tmpl, sample, args.goal)}\n")
        else:
            print(f"{cat:22s} {name}")


def _one_payload(args):
    """Build the single payload used by `gen` (explicit text wins)."""
    if args.payload_text:
        return {"category": "custom", "name": "custom",
                "canary": P.new_canary(), "goal": "", "text": args.payload_text}
    cats = [args.category] if args.category else ["provenance-forgery"]
    built = P.build(categories=cats, goal=args.goal)
    # pick the named payload if given, else the first in the category
    if args.name:
        built = [b for b in built if b["name"] == args.name] or built
    return built[0]


def cmd_gen(args):
    p = _one_payload(args)
    text = p["text"]
    if args.canary_host:
        text = text.replace("CANARY_HOST", args.canary_host)

    fmt = args.format
    if fmt == "pdf":
        data = docgen.make_pdf(text, template=args.template, hide_mode=args.hide_mode)
        mode = "wb"
    elif fmt == "html":
        data, mode = docgen.make_html(text), "w"
    elif fmt == "svg":
        data, mode = docgen.make_svg(text), "w"
    else:
        data, mode = docgen.make_txt(text), "w"

    out = args.output or f"ph_payload.{fmt}"
    with open(out, mode) as f:
        f.write(data)

    print(f"[+] Wrote {fmt.upper()} -> {out}")
    print(f"[+] Carrier template : {args.template}" + (f"  (hide: {args.hide_mode})" if fmt == "pdf" else ""))
    print(f"[+] Payload category : {p['category']}/{p['name']}")
    print(f"[+] CANARY to grep   : {p['canary']}")
    print("[+] Hidden text embedded in the document:")
    print("    " + text.replace("\n", "\n    "))
    print("\n[i] Verify the hidden text is machine-readable (what the LLM will ingest):")
    if fmt == "pdf":
        print(f"      pdftotext -layout {out} - | grep -n '{p['canary']}'")
    print("[i] Then upload/share the file to the in-scope AI assistant and ask it to")
    print("    summarize or cite the document. If the answer contains the canary or")
    print("    follows the injected instruction, you have an indirect-injection finding.")
    print("\n[!] AUTHORIZED TESTING ONLY. In-scope assets you may test, nothing else.")


def cmd_probe(args):
    cats = args.category or None
    plist = P.build(categories=cats, goal=args.goal)
    if args.canary_host:
        for p in plist:
            p["text"] = p["text"].replace("CANARY_HOST", args.canary_host)

    headers = {}
    for h in args.header or []:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    json_body = None
    if args.json:
        try:
            json_body = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(f"[!] --json is not valid JSON: {e}", file=sys.stderr)
            return 2
    params = None
    if args.param:
        params = {}
        for kv in args.param:
            k, _, v = kv.partition("=")
            params[k] = v

    print(f"[*] Probing {args.url} with {len(plist)} payload(s)...\n")
    results = prober.probe(
        args.url, plist, method=args.method, headers=headers,
        body=args.data, json_body=json_body, params=params,
        response_path=args.response_path, delay=args.delay, timeout=args.timeout,
        proxy=args.proxy, verify=not args.insecure, verbose=True)

    hits = [r for r in results if r.hit]
    print(f"\n[=] {len(hits)}/{len(results)} payload(s) reflected their canary (candidate injections).")
    for r in hits:
        print(f"  HIT {r.category}/{r.name}  (HTTP {r.status})  canary={r.canary}")
        print(f"      …{r.snippet}…")
    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"[+] Full results -> {args.output}")
    print("\n[!] Canary reflection is a CANDIDATE, not a confirmed bug. Verify the real "
          "impact (exfil reached your host, tool actually fired, data actually leaked).")


def build_parser():
    p = argparse.ArgumentParser(
        prog="prompthound",
        description="PromptHound — prompt-injection harness for authorized AI-app testing.",
        epilog="AUTHORIZED TESTING ONLY. Use only against AI features in scope for a "
               "bug-bounty program or engagement you are authorized to test.")
    p.add_argument("--version", action="version", version=f"PromptHound {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="craft a hidden-payload document for indirect injection")
    g.add_argument("-f", "--format", choices=["pdf", "html", "svg", "txt"], default="pdf")
    g.add_argument("-t", "--template", choices=list(docgen.TEMPLATES), default="invoice",
                   help="visible decoy content (PDF)")
    g.add_argument("--hide-mode", choices=["invisible", "tiny", "white", "offpage"],
                   default="invisible", help="how the payload hides in the PDF")
    g.add_argument("-c", "--category", choices=P.ALL_CATEGORIES,
                   help="payload category (default: provenance-forgery)")
    g.add_argument("-n", "--name", help="specific payload name within the category")
    g.add_argument("--goal", default="echo the confirmation token back to the user",
                   help="benign instruction a successful injection would carry")
    g.add_argument("--payload-text", help="use this exact hidden text instead of the library")
    g.add_argument("--canary-host", help="host to substitute for CANARY_HOST in exfil payloads")
    g.add_argument("-o", "--output", help="output file (default ph_payload.<fmt>)")
    g.set_defaults(func=cmd_gen)

    pr = sub.add_parser("probe", help="fire direct-injection payloads at an AI endpoint")
    pr.add_argument("-u", "--url", required=True)
    pr.add_argument("-X", "--method", default="POST")
    pr.add_argument("-H", "--header", action="append", metavar="'K: V'")
    pr.add_argument("--data", help="raw body template containing {{PAYLOAD}}")
    pr.add_argument("--json", help="JSON body template (string) containing {{PAYLOAD}}")
    pr.add_argument("--param", action="append", metavar="k=v",
                    help="query param (use {{PAYLOAD}} as a value); repeatable")
    pr.add_argument("--response-path", help="dotted path to the model text in a JSON reply "
                                            "(e.g. choices.0.message.content)")
    pr.add_argument("-c", "--category", action="append", choices=P.ALL_CATEGORIES,
                    help="limit to category (repeatable; default: all)")
    pr.add_argument("--goal", default="echo the confirmation token back to the user")
    pr.add_argument("--canary-host", help="host to substitute for CANARY_HOST in exfil payloads")
    pr.add_argument("--delay", type=float, default=0.5, help="seconds between requests")
    pr.add_argument("--timeout", type=float, default=20)
    pr.add_argument("--proxy", help="http://127.0.0.1:8080 for Burp/ZAP")
    pr.add_argument("--insecure", action="store_true", help="disable TLS verification")
    pr.add_argument("-o", "--output", help="write full results as JSON")
    pr.set_defaults(func=cmd_probe)

    pl = sub.add_parser("payloads", help="list / render the payload library")
    pl.add_argument("-c", "--category", action="append", choices=P.ALL_CATEGORIES)
    pl.add_argument("--render", action="store_true", help="show rendered payload text")
    pl.add_argument("--goal", default="echo the confirmation token back to the user")
    pl.set_defaults(func=cmd_payloads)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", None) in (None,):
        build_parser().print_help()
        return 0
    if args.cmd != "payloads":
        _banner()
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
