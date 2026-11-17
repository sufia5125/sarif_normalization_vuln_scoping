from collections import deque
#TBD: make these more comprehensive and realistic
PARENT = {
    23: 22,                  # Relative path traversal -> Path traversal
    36: 706,                 # Absolute path traversal -> Incorrectly-resolved name/reference
    78: 77,                  # OS command injection -> Command injection
    77: 74,                  # Command injection -> Injection
    79: 74,                  # XSS -> Injection
    89: 74,                  # SQL injection -> Injection
    943: 74,                 # Query-logic injection -> Injection
    94: 74,                  # Code injection -> Injection
    95: 94,                  # Eval injection -> Code injection
}

def _neighbors():
    g = {}
    for child, parent in PARENT.items():
        g.setdefault(child,set()).add(parent)
        g.setdefault(parent,set()).add(child)
    return g

_G = _neighbors()

def distance(a, b, limit):
    if a==b:
        return 0
    seen, q= {a}, deque([(a,0)])
    while q:
        node, d = q.popleft()
        if d==limit:
            continue
        for next in _G.get(node,()):
            if next == b :
                return d + 1
            if next not in seen:
                seen.add(next)
                q.append((next, d+1))
    return None