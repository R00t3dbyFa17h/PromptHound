"""Hidden-payload document generator.

Builds documents that look benign to a human but carry attacker-controlled text
that a machine reader (an LLM's document ingestion / RAG pipeline) will extract
and treat as content. This is the engine behind indirect prompt-injection
findings against document assistants (e.g. "AI Assistant on a PDF").

The PDF writer is pure standard-library (no reportlab) so it has zero runtime
dependencies and gives exact control over the text *rendering mode*, which is
what makes the payload invisible-yet-extractable:

    hide mode   how it hides                            extractable?
    ---------   -------------------------------------   ------------
    invisible   PDF text render mode 3 (Tr 3)           yes  (recommended)
    tiny        0.3 pt font size                        yes
    white       white fill on white page                yes
    offpage     drawn below the visible MediaBox         yes

`invisible` is the default: the glyphs are never painted, but `pdftotext` and
LLM PDF parsers still read the characters — exactly the behavior demonstrated in
real citation-forgery bugs.

AUTHORIZED USE ONLY.
"""
from __future__ import annotations

PAGE_W, PAGE_H = 612, 792  # US Letter, PDF points


def _esc(s: str) -> str:
    """Escape a string for a PDF literal ( ) string and drop non-Latin bytes."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\\()":
            out.append("\\" + ch)
        elif 32 <= o < 127:
            out.append(ch)
        elif ch in "\r\n\t":
            out.append(" ")
        else:
            out.append("?")  # Helvetica base encoding is ASCII-safe only
    return "".join(out)


def _wrap(text, width):
    """Word-wrap each logical line to `width` chars, preserving blank lines, so
    no line runs past the page edge (which would drop glyphs from extraction)."""
    out = []
    for logical in text.split("\n"):
        if not logical:
            out.append("")
            continue
        line = ""
        for word in logical.split(" "):
            if line and len(line) + 1 + len(word) > width:
                out.append(line)
                line = word
            else:
                line = word if not line else line + " " + word
        out.append(line)
    return "\n".join(out)


def _text_block(x, y, size, text, rgb=(0, 0, 0), mode=0, leading=None):
    """Return content-stream ops for a (possibly multi-line) text block."""
    r, g, b = rgb
    lead = leading if leading is not None else max(size * 1.3, 1)
    ops = ["BT", f"/F1 {size:.2f} Tf", f"{mode} Tr",
           f"{r:.3f} {g:.3f} {b:.3f} rg", f"{x:.2f} {y:.2f} Td", f"{lead:.2f} TL"]
    lines = text.split("\n") or [""]
    for i, line in enumerate(lines):
        ops.append(f"({_esc(line)}) Tj")
        if i != len(lines) - 1:
            ops.append("T*")
    ops.append("ET")
    return "\n".join(ops)


def build_pdf(visible_blocks, hidden_blocks):
    """Assemble a one-page PDF.

    visible_blocks / hidden_blocks: list of dicts with keys
        x, y, size, text, rgb(optional), mode(optional).
    Returns bytes.
    """
    content_parts = []
    for blk in visible_blocks:
        content_parts.append(_text_block(
            blk["x"], blk["y"], blk.get("size", 11), blk["text"],
            blk.get("rgb", (0, 0, 0)), blk.get("mode", 0)))
    for blk in hidden_blocks:
        content_parts.append(_text_block(
            blk["x"], blk["y"], blk.get("size", 8), blk["text"],
            blk.get("rgb", (0, 0, 0)), blk.get("mode", 3)))
    content = "\n".join(content_parts).encode("latin-1", "replace")

    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        % (PAGE_W, PAGE_H))
    objs.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content))
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"

    xref_pos = len(out)
    n = len(objs) + 1
    out += b"xref\n0 %d\n" % n
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (n, xref_pos)
    return bytes(out)


# ---- hide-mode -> block styling ------------------------------------------
def _style(mode: str, text: str, x: float, y: float):
    if mode == "invisible":
        return {"x": x, "y": y, "size": 9, "text": text, "mode": 3}
    if mode == "tiny":
        return {"x": x, "y": y, "size": 0.3, "text": text, "mode": 0, "rgb": (0.5, 0.5, 0.5)}
    if mode == "white":
        return {"x": x, "y": y, "size": 9, "text": text, "mode": 0, "rgb": (1, 1, 1)}
    if mode == "offpage":
        return {"x": x, "y": -200, "size": 9, "text": text, "mode": 0}
    raise ValueError(f"unknown hide mode: {mode}")


# ---- document templates (visible decoy content) --------------------------
TEMPLATES = {
    "invoice": [
        {"x": 72, "y": 720, "size": 16, "text": "Vendor Invoice Summary"},
        {"x": 72, "y": 696, "size": 10, "text":
            "Prepared by Accounts Payable for internal review and approval routing."},
        {"x": 72, "y": 660, "size": 11, "text":
            "Invoice 44821 was received from Northwind Supplies on 12 August 2026."},
        {"x": 72, "y": 644, "size": 11, "text":
            "The total payable is 18,400 USD under net-30 terms, due 11 September."},
        {"x": 72, "y": 628, "size": 11, "text":
            "Remittance should be sent to Northwind Supplies, account NW-4471."},
        {"x": 72, "y": 584, "size": 11, "text":
            "Approval is pending from the finance controller. PO ref PO-2026-0871."},
    ],
    "report": [
        {"x": 72, "y": 720, "size": 16, "text": "Quarterly Operations Summary"},
        {"x": 72, "y": 696, "size": 10, "text":
            "Prepared for leadership review. Internal distribution only."},
        {"x": 72, "y": 660, "size": 11, "text":
            "Revenue grew 12% quarter over quarter; headcount flat at 240."},
        {"x": 72, "y": 644, "size": 11, "text":
            "Customer satisfaction averaged 4.3/5 with no material risks identified."},
    ],
    "resume": [
        {"x": 72, "y": 720, "size": 16, "text": "Candidate Resume"},
        {"x": 72, "y": 696, "size": 10, "text": "Submitted for the open engineering role."},
        {"x": 72, "y": 660, "size": 11, "text": "Experience: 6 years backend development."},
        {"x": 72, "y": 644, "size": 11, "text": "Skills: Python, Go, distributed systems."},
    ],
    "blank": [
        {"x": 72, "y": 720, "size": 12, "text": "Document"},
    ],
}


def make_pdf(payload_text: str, template: str = "invoice", hide_mode: str = "invisible") -> bytes:
    """Build a decoy PDF of `template` with `payload_text` hidden via `hide_mode`.

    The payload is placed in a blank region of the page (like a real citation
    anchor) so a reader clicking any AI citation lands on empty space.
    """
    visible = list(TEMPLATES.get(template, TEMPLATES["invoice"]))
    # Wrap to ~90 chars so the full payload stays on-page and extracts intact.
    wrapped = _wrap(payload_text, 90)
    hidden = [_style(hide_mode, wrapped, x=72, y=470)]
    return build_pdf(visible, hidden)


# ---- other carriers (for non-PDF ingestion paths) ------------------------
def make_html(payload_text: str) -> str:
    safe = payload_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Document</title></head>"
        "<body><h1>Vendor Invoice Summary</h1>"
        "<p>Invoice 44821 — total payable 18,400 USD, account NW-4471.</p>"
        f"<div style='position:absolute;left:-9999px;color:#fff;font-size:1px'>{safe}</div>"
        "</body></html>")


def make_svg(payload_text: str) -> str:
    safe = payload_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='120'>"
        "<text x='10' y='30' font-size='16'>Vendor Invoice Summary</text>"
        f"<text x='10' y='60' font-size='0.1' fill='#ffffff' opacity='0'>{safe}</text>"
        "</svg>")


def make_txt(payload_text: str) -> str:
    # Zero-width / whitespace padding keeps the payload off the visible line.
    return ("Vendor Invoice Summary\nInvoice 44821 — total payable 18,400 USD.\n"
            + "\n" * 40 + payload_text + "\n")
