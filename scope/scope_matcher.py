#directly borrows from scope+offset

def match_scope(scopes, line):
    candidates = [s for s in scopes if s.start <= line <= s.end]
    if not candidates:
        return scopes[0]

    return min(candidates, key=lambda s: (s.end - s.start, -s.depth))