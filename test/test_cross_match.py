from normalization.match.cross_match import is_match, group_findings
from normalization.data.schema import NormalizedFinding


def nf(tool, line, cwes, scope="A.java::A[0]::foo[0]", file="A.java", offset=1):
    return NormalizedFinding(tool=tool, rule_id="r", file=file, start_line=line,
                             end_line=line, cwes=cwes, severity="error", message="m",
                             id=f"{tool}-{line}", scope_tag=scope, scope_kind="method",
                             offset=offset)


def test_same_scope_same_cwe_different_lines_match():
    assert is_match(nf("s", 12, [89]), nf("c", 14, [89], offset=3))

def test_same_tool_never_matches():
    assert not is_match(nf("s", 12, [89]), nf("s", 13, [89]))

def test_different_scope_does_not_match():
    assert not is_match(nf("s", 12, [89]), nf("c", 12, [89], scope="A.java::A[0]::bar[0]"))

def test_missing_cwe_does_not_match():
    assert not is_match(nf("s", 12, []), nf("c", 12, [89]))

def test_family_needs_k():
    a, b = nf("s", 12, [89]), nf("c", 12, [943])
    assert not is_match(a, b, k=0)
    assert is_match(a, b, k=1)

def test_rule3_optional():
    a, b = nf("s", 12, [89], offset=1), nf("c", 14, [89], offset=3)
    assert is_match(a, b)
    assert not is_match(a, b, rule3=True, delta=0)
    assert is_match(a, b, rule3=True, delta=2)

def test_agreement_count():
    g = group_findings([nf("s", 12, [89]), nf("c", 14, [89]), nf("s", 40, [79], scope="x")])
    assert sorted(x["agreement_count"] for x in g) == [1, 2]
