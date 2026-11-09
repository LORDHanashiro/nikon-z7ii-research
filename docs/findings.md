# Findings and evidence matrix

| Finding | Grade and scope | Locations / relationship |
|---|---|---|
| Dp has its own conditional configuration path; no D0==Dp assumption is needed for that local path | VERIFIED static locations; composite active-instance path INFERRED | MAS 1030CADE, 1026357A, 10265DEC, 10269A6E |
| Software format validation and submission fields exist | VERIFIED static; physical HDMI effect UNKNOWN | MAS 1047EC00 and descriptor consumers |
| Descriptor address words reach two q-selected software port families | VERIFIED local static expressions; hardware DMA UNKNOWN | MAS 102C05EE, 102E53B6, 1036A5D0, 1036A97A; S565–S582, H016–H017 |
| Profile/level and SPS-like configuration candidates exist | INFERRED semantics; raw configuration relationships are static findings | MAS 104B90EE / 104B949C; not evidence of High 10 support |
| A CPU conversion path narrows components to bytes | VERIFIED local static exclusion only | MAS 102B3B82; does not exclude wider upstream or other paths |
| RAW row-capacity expressions are consistent with several wider layouts under explicit unit assumptions | INFERRED; packing and actual valid bits UNKNOWN | MAS 1023994C / 1023C830 and software submission family |
| A provided-descriptor recording API has separate status/count roles | VERIFIED static software contract; count units/consumption/durability UNKNOWN | MAS 105671BA / 105BEA78 |
| Independent host fixtures preserve synthetic 10-bit codes and reject selected faults | VERIFIED finite host tests only | Self-authored tools; no Nikon pixels or camera recording |

There is no verified end-to-end sensor → accessible genuine N-Log frame → 10-bit encoder or alternative recorder → internal card path. Encoder support, silicon incapability, complete boot, menu functionality and working internal recording are not conclusions of this repository.
