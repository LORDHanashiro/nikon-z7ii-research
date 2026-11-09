# Restore analysis metadata locally

Use a separate analysis project containing a lawfully obtained matching raw component at the listed base. Run RestorePublicAnnotations.java with two arguments: path to indexes/annotation-recipe.json and MAS, SLA or EX. The script hashes the complete local module before changing metadata and refuses mismatches.

It restores AN_ labels, evidence comments and partial type definitions only. It does not modify bytes, create code/functions, force ARM/Thumb context, invent xrefs or populate RAM. Data types are not applied to runtime objects. Components remain separate even when numerical addresses overlap. Back up your analysis project first.

This recipe intentionally omits proprietary byte guards and original excerpts. Full-module SHA-256 verification remains required. A label is not a recovered Nikon symbol, a proven function boundary or hardware validation.
