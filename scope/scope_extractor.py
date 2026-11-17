import sys
from .parser import parse_java
from ..data.schema import Scope

#for deep nesting
sys.setrecursionlimit(10000)

SCOPE_KINDS = {
    "class_declaration": "class",
    "interface_declaration": "class",
    "enum_declaration": "class",
    "record_declaration":"class",
    "method_declaration": "method",
    "constructor_declaration": "method",
}

def extract_scopes(file_path: str, source: bytes) -> list[Scope]:
    tree = parse_java(source)
    total_lines = source.count(b"\n")+1
    scopes = [Scope(tag=file_path, kind="file", start=1, end=total_lines, depth=0)]
    
    def visit(node, parent_tag, counters, depth):
        if node.type in SCOPE_KINDS:
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else "<anon>"
            idx = counters.get( name, 0 )
            counters[name] = idx+1              #for overloaded methods
            tag= f"{parent_tag}::{name}[{idx}]"
            scopes.append(Scope(tag, SCOPE_KINDS[node.type],
                                node.start_point[0] + 1,
                                node.end_point[0] + 1,
                                depth + 1))
            child_counters= {}
            for ch in node.children:
                visit (ch, tag, child_counters, depth+1)

        else:
            for ch in node.children:
                visit(ch, parent_tag, counters, depth)
                
    visit(tree.root_node, file_path, {}, 0)
    return scopes