# Nikon Z7 II C1.70 — genuine 10-bit N-Log internal-recording research

[中文说明](README.zh-CN.md)

**Genuine 10-bit-effective N-Log internal card recording has NOT been implemented. The original encoder's 10-bit capability is NOT established.** No confirmed accessible true-10-bit N-Log frame source has been recovered. The project does not accept 8-bit expansion, simulated Log, metadata changes or synthetic fixtures as camera success.

This is a publication snapshot of existing offline work, not new firmware analysis or a firmware release. Research execution is currently blocked on pixel-source, format/precision, ownership and hardware-interface evidence.

* [Findings and evidence matrix](docs/findings.md)
* [Architecture and data flow](docs/architecture.md)
* [HDMI / N-Log](docs/hdmi-nlog.md), [H.264](docs/encoder.md), [RAW](docs/raw.md)
* [Corrections and excluded hypotheses](docs/corrections.md)
* [Evidence definitions and limits](docs/evidence.md)
* [MAS/SLA/EX location index](indexes/functions.csv), [partial structures](indexes/structures.json), [relations](indexes/relations.csv)
* [Ghidra metadata restoration](ghidra/README.md)
* [Independent synthetic host tools and tests](tests/test_public_tools.py)
* [Third-party references and licenses](THIRD_PARTY.md), [rights notice](COPYRIGHT.md)

VERIFIED always has a stated scope. Verified original static instructions, original natural execution in a fixed QEMU model, QEMU functional assumptions, synthetic host tests and physical-camera evidence are different classes. The public indices intentionally omit original bytes, disassembly, decompilation, captures and private evidence paths. Public availability of an index is not independent verification of withheld raw evidence.

This snapshot contains no camera firmware, decrypted modules, keys, RAM/NVRAM dumps, camera identifiers or Ghidra databases. It has no CI workflows and performs no camera operations. Third-party implementations are referenced, not bundled.

Run the host-only checks with `python3 -m unittest discover -s tests -v`. Building the optional synthetic recorder requires a C++20 compiler; its format and data are self-authored test fixtures, not Nikon N-Log. No camera performance claim follows from these tests.

Publication updates are prepared locally and audited before any public push. See [synchronization](docs/synchronization.md). The private backup is never used as a Git parent or remote source for this repository. Automated refresh updates reviewed indices/tools; descriptive conclusions remain an owner-reviewed snapshot and must be revised in the publication generator before making new claims.
