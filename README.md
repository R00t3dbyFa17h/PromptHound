<h1 align="center">🐺 PromptHound</h1>

<h4 align="center">A prompt-injection harness for authorized AI-application testing</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Deps-stdlib%20only*-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-AI%20%2F%20LLM%20Security-8A63D2?style=for-the-badge">
</p>

<p align="center">
  <a href="#-what-it-does">What it does</a> •
  <a href="#-install">Install</a> •
  <a href="#-indirect-injection-hidden-payload-docs">Indirect injection</a> •
  <a href="#-direct-injection-probing-an-endpoint">Direct injection</a> •
  <a href="#-payload-library">Payloads</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

> ⚖️ **Authorized testing only.** PromptHound is for AI features that are **in
> scope** for a bug-bounty program or an engagement you are authorized to test.
> It generates attack-shaped content; using it against systems you don't have
> permission to test may be illegal.

---

## 📖 What it does

Modern products wrap LLMs around your documents and data — PDF assistants, RAG
search, copilots, agents. The highest-impact, lowest-duplicate bug class there is
**prompt injection**: untrusted content steering the model into fabricating
"verified" facts, leaking hidden context, exfiltrating data through its output,
or invoking tools it shouldn't.

PromptHound productizes that workflow:

| Component | What it gives you |
| :--- | :--- |
| **`gen`** | A **hidden-payload document generator** — crafts a PDF (or HTML/SVG/TXT) that looks benign to a human but carries attacker text a machine reader extracts and obeys. This is the indirect-injection vector behind real citation-forgery bugs. |
| **`probe`** | A **direct-injection prober** — fires the payload library at an AI HTTP endpoint and flags any response that reflects the payload's unique **canary**. |
| **`payloads`** | A **categorized payload library** with canary templating: instruction override, provenance/citation forgery, output-handling exfil, tool/function abuse, system-prompt leak, cross-context. |

\* `gen` and the payload library are pure standard library — the pure-Python PDF
writer needs no `reportlab`. Only `probe` needs `requests` (`pip install
prompthound[probe]`).

---

## 🚀 Install

```bash
git clone https://github.com/R00t3dbyFa17h/PromptHound.git
cd PromptHound
pip install .            # or: pip install ".[probe]" for the HTTP prober
```

Run without installing: `python3 -m prompthound ...`

---

## 🫥 Indirect injection: hidden-payload docs

Craft a document whose **visible** text is an innocent invoice but whose
**machine-readable** text tells the assistant to cite a fabricated figure:

```bash
prompthound gen -f pdf -t invoice -c provenance-forgery \
    --goal "184,000 USD to account NW-9920" -o evil.pdf
```

PromptHound prints the unique **canary** and the exact hidden text. Confirm the
payload is what a model will ingest (invisible to a human, plain to a parser):

```bash
pdftotext -layout evil.pdf -      # visible decoy AND the hidden injection both appear
```

Then **upload/share `evil.pdf` to the in-scope AI assistant** and ask it to
summarize or state the figure. If it returns your injected value — or the canary —
and its "verify source"/citation resolves to the hidden text, you have an
indirect prompt-injection finding with a clean before/after PoC.

**Hide modes** (`--hide-mode`): `invisible` (PDF render-mode 3, default — never
painted, still extracted), `tiny` (0.3 pt), `white` (white-on-white), `offpage`
(drawn below the page). **Carriers** (`-f`): `pdf`, `html`, `svg`, `txt`.
**Decoys** (`-t`): `invoice`, `report`, `resume`, `blank`.

---

## 🎯 Direct injection: probing an endpoint

Describe the AI endpoint's request shape once, with `{{PAYLOAD}}` where the
user-controlled prompt goes:

```bash
prompthound probe \
    -u https://target.example/api/assistant \
    -H "Authorization: Bearer $TOKEN" \
    --json '{"message":"{{PAYLOAD}}"}' \
    --response-path choices.0.message.content \
    --proxy http://127.0.0.1:8080
```

It substitutes each payload, sends it (through Burp if you pass `--proxy`), and
reports which ones reflected their canary. `--response-path` pulls the model's
text out of a JSON reply before matching. Canary reflection is a **candidate** —
verify the real impact before reporting.

---

## 🧰 Payload library

```bash
prompthound payloads                       # list
prompthound payloads -c tool-abuse --render --goal "read /etc/passwd"
```

| Category | Tests for |
| :--- | :--- |
| `instruction-override` | Does untrusted text override prior instructions? |
| `provenance-forgery` | Will the assistant cite attacker text as the verified source? |
| `data-exfil-output` | Insecure output handling — markdown-image / link exfiltration |
| `tool-abuse` | Can injected text trigger an unauthorized tool/function call? |
| `prompt-leak` | System-prompt / hidden-context disclosure |
| `cross-context` | Cross-session / cross-tenant leakage |

Payloads wrap the goal in forged chat-template delimiters
(`</document> <|eot_id|> [/INST] <<SYS>>`) and tag it with a greppable canary so
you can prove ingestion.

---

## ⚠️ Disclaimer

**FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.** You are responsible for
having explicit permission to test any target, and for obeying all applicable
laws and the rules of the program you are testing under. The author assumes no
liability for misuse. Do not use PromptHound to deceive or defraud real users,
or against any AI system that is not in scope for your engagement.

---

<p align="center"><b>Built by R00t3dbyFa17h</b> · pairs with
<a href="https://github.com/R00t3dbyFa17h/ZeroRecon">ZeroRecon</a> &amp;
<a href="https://github.com/R00t3dbyFa17h/WAF-Whisper">WAF-Whisper</a></p>
