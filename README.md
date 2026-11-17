takes SARIF input and normalizes to a common schema 
then matches vulnerability according to rules outlined in Scope+Offset (2025) without the temporal offset aspect 
so a vulnerability v1 and v2 are considered same iff they come from different scanners, they belong to the same scope and CWE categories
