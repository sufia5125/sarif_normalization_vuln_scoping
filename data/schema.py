#define the output schema here
from dataclasses import dataclass

@dataclass
class RawFinding:
    tool: str            #tool name
    rule_id: str         
    file: str            #relative to repo root
    start_line: int      
    end_line: int
    cwes: list[int]      # one rule can carry multiple CWEs
    severity: str        #scanner's assigned severity label
    message: str

@dataclass
class Scope:
    tag: str             
    kind: str            #"file"|"class"|"method" 
    start: int
    end: int
    depth: int

@dataclass
class NormalizedFinding(RawFinding):
    id: str
    scope_tag: str
    scope_kind: str
    offset: int          # start_line-scope.start, for diagnostics