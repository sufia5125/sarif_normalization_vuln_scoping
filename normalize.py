import argparse, json
from fnmatch import fnmatch
from dataclasses import asdict
from pathlib import Path
from collections import Counter
from .adapters.codeql_adapter import load_sarif
from .scope.scope_extractor import extract_scopes
from .scope.scope_matcher import match_scope
from .data.schema import NormalizedFinding, Scope

def normalize(sarif_paths, repo_root, include=None):
    repo_root = Path(repo_root).resolve()
    raw = [f for p in sarif_paths for f in load_sarif(p, repo_root)]
    if include:   # optional paths
        raw = [f for f in raw if any(fnmatch(f.file, g) for g in include)]
    cache, out, skipped = {}, [], Counter()

    for i, r in enumerate(raw):
        if r.file not in cache:
            fp = repo_root / r.file
            if fp.suffix == ".java" and fp.exists():
                cache[r.file] = extract_scopes(r.file, fp.read_bytes())
            else:
                skipped["non-java-or-missing"] += 1
                cache[r.file] = [Scope(r.file, "file", 1, 10**9, 0)]
        scope = match_scope(cache[r.file], r.start_line)
        out.append(NormalizedFinding(
            **asdict(r),
            id=f"{r.tool}-{i}",
            scope_tag=scope.tag,
            scope_kind=scope.kind,
            offset=r.start_line - scope.start,
        ))
    return out, skipped

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sarif", nargs="+", required=True)
    ap.add_argument("--out", default="outputs/02_normalized.json")
    ap.add_argument("--include", nargs="*", default=None, help="path globs to keep")
    a = ap.parse_args()
    findings, skipped = normalize(a.sarif, a.repo, a.include)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps([asdict(f) for f in findings], indent=2))

    print(f"{len(findings)} findings; skipped/file-scope-only: {dict(skipped)}")
    print("by tool:", Counter(f.tool for f in findings))
    print("by scope kind:", Counter(f.scope_kind for f in findings))
    print("no CWE:", sum(1 for f in findings if not f.cwes))