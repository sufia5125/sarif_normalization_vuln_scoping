#convert to SARIF
import json, re
from pathlib import Path
from urllib.parse import unquote, urlparse
from ..data.schema import RawFinding

CWE_RE = re.compile(r"cwe[-_]?(\d+)", re.IGNORECASE)

#get the cwe families from the rules fired from the sast engines
def _cwes_from_tags(tags):
    found =[]
    for t in tags or []:
        for m in CWE_RE.finditer(t):
            n=int(m.group(1))
            if n not in found:
                found.append(n)
    
    return found

#get the path to the source code file
def _clean_uri(uri, repo_root: Path):
    """Map a SARIF URI to a path relative to repo_root.

    Scanners write different forms (e.g. Semgrep '/src/src/main/java/A.java' from a
    container, CodeQL 'src/main/java/A.java'). Try progressively shorter suffixes of the
    path until one exists under repo_root; never resolves outside repo_root.
    """
    path = unquote(urlparse(uri).path) if uri.startswith("file:") else unquote(uri)
    parts = [x for x in Path(path).as_posix().split("/") if x]
    if ".." not in parts:
        for i in range(len(parts)):
            cand = "/".join(parts[i:])
            if (repo_root / cand).is_file():
                return cand
    return Path(path).as_posix()      # unresolved: keep as-is (normalize() flags it)

def _rule_table(run):
    comps = [run["tool"]["driver"]] + run["tool"].get("extensions", [])
    table = {}
    for c in comps:
        for r in c.get("rules", []):
            table[r["id"]] = r
    return table

def load_sarif(sarif_path, repo_root) -> list[RawFinding]:
    repo_root = Path(repo_root).resolve()
    data = json.loads(Path(sarif_path).read_text(encoding='utf-8'))
    out = []
    
    for run in data.get("runs", []):
        tool = run["tool"]["driver"]["name"]
        rules = _rule_table(run)
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id","")
            rule = rules.get(rule_id,{})
            loc = res["locations"][0]["physicalLocation"]
            region = loc.get("region", {})
            start = region.get("startLine")
            if start is None:
                continue
            out.append(RawFinding(
                tool=tool,
                rule_id=rule_id,
                file=_clean_uri(loc["artifactLocation"]["uri"], repo_root),
                start_line=start,
                end_line=region.get("endLine", start),
                cwes= _cwes_from_tags(rule.get("properties",{}).get("tags")),
                severity=res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning"),
                message=res.get("message",{}).get("text","")
            ))
            
    return out
