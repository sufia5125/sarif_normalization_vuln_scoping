#parse the source code pointed at in original repo
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

_parser = Parser(Language(tsjava.language()))

def parse_java(source: bytes):
    return _parser.parse(source)