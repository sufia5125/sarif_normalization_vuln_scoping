from normalization.scope.scope_extractor import extract_scopes
from normalization.scope.scope_matcher import match_scope

JAVA = b"""package p;
public class A {
    void foo() {
        int x = 1;
    }
    void foo(int a) {
        int y = 2;
    }
}
"""

def test_tags_and_lines():
    s = {x.tag: (x.start, x.end) for x in extract_scopes("A.java", JAVA)}
    assert s["A.java::A[0]"] == (2, 9)
    assert s["A.java::A[0]::foo[0]"] == (3, 5)
    assert s["A.java::A[0]::foo[1]"] == (6, 8)

def test_matching_and_offset():
    scopes = extract_scopes("A.java", JAVA)
    m = match_scope(scopes, 4)
    assert m.tag.endswith("foo[0]") and 4 - m.start == 1
    assert match_scope(scopes, 7).tag.endswith("foo[1]")
    assert match_scope(scopes, 2).kind == "class"   # class header line, no method