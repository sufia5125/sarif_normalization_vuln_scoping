import argparse, json
from collections import defaultdict, Counter
from dataclasses import asdict
from pathlib import Path
from .cwe_hiearchy import distance


def cwe_related(a, b, k=0):
    if not a or not b:                      # no CWE reported 
        return False
    if set(a) & set(b):
        return True
    if k >= 1:
        return any(distance(x, y, k) is not None for x in a for y in b)
    return False


def is_match(v1, v2, k=0):
    if v1.tool == v2.tool:                                          
        return False
    if v1.file != v2.file or v1.scope_tag != v2.scope_tag:          
        return False
    if not cwe_related(v1.cwes, v2.cwes, k):                        
        return False
    return True


def _snippet(repo_root, f):
    try:
        lines = (Path(repo_root) / f.file).read_text(encoding="utf-8").splitlines()
        return "\n".join(lines[f.start_line - 1:f.end_line]).strip()
    except Exception:
        return None


def group_findings(findings, k=0, repo_root=None):
    parent = list(range(len(findings)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    buckets = defaultdict(list)             # only compare findings sharing file+scope
    for i, f in enumerate(findings):
        buckets[(f.file, f.scope_tag)].append(i)
    for idxs in buckets.values():
        for x in idxs:
            for y in idxs:
                if x < y and is_match(findings[x], findings[y], k):
                    parent[find(x)] = find(y)

    comps = defaultdict(list)
    for i, f in enumerate(findings):
        comps[find(i)].append(f)

    report = []
    for n, members in enumerate(sorted(comps.values(),
                                       key=lambda m: (m[0].file, m[0].start_line)), 1):
        tools = sorted({m.tool for m in members})
        
        #schema
        report.append({
            "group_id": f"g{n}",
            "file": members[0].file,
            "scope_tag": members[0].scope_tag,
            "scope_kind": members[0].scope_kind,
            "cwes": sorted({c for m in members for c in m.cwes}),
            "tools": tools,
            "agreement_count": len(tools),
            "same_tool_duplicates": len(members) > len(tools),   # chaining flag
            "config": {"family_depth_k": k},
            "members": [{
                "id": m.id, "tool": m.tool, "rule_id": m.rule_id,
                "line": m.start_line, "end_line": m.end_line, "offset": m.offset,
                "cwes": m.cwes, "severity": m.severity, "message": m.message,
                "snippet": _snippet(repo_root, m) if repo_root else None,
            } for m in members],
        })
    return report


def summarize(report):
    dist = Counter(g["agreement_count"] for g in report)
    print(f"{len(report)} groups | agreement distribution: {dict(sorted(dist.items()))}")
    # for g in report:
    #     print(f"  {g['group_id']:>4}  agree={g['agreement_count']}  "
    #           f"CWE={g['cwes']}  {g['tools']}  {g['scope_tag']}")
    # flagged = [g["group_id"] for g in report if g["same_tool_duplicates"]]
    # if flagged:
    #     print("  note: groups with >1 finding from one tool (possible chaining):", flagged)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--normalized", default="outputs/02_normalized.json")
    ap.add_argument("--repo", default=None, help="repo root, to attach code snippets")
    ap.add_argument("--out", default="outputs/03_matched.json")
    ap.add_argument("--family-depth", type=int, default=0)
    a = ap.parse_args()
    from ..data.schema import NormalizedFinding
    fs = [NormalizedFinding(**d) for d in json.loads(Path(a.normalized).read_text())]
    rep = group_findings(fs, a.family_depth, a.repo)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(rep, indent=2))
    summarize(rep)
