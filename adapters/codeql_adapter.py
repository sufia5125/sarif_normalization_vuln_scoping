import re
from dataclasses import replace
from .semgrep_adapter import load_sarif as _load_shared


#codeql has too long msgs
def _short_message(text, max_chars=400):
    lines = [l for l in text.splitlines() if l.strip()]
    unique = list(dict.fromkeys(re.sub(r"\(\d+\)", "", l).strip() for l in lines))
    msg = " | ".join(unique)
    if len(lines) > len(unique):
        msg += f" [x{len(lines)} source paths]"
    return msg[:max_chars]


def load_sarif(sarif_path, repo_root):
    findings = _load_shared(sarif_path, repo_root)
    return [replace(f, message=_short_message(f.message)) if f.tool == "CodeQL" else f
            for f in findings]