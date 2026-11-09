# Architecture and data flow

The hardware/signal map retains CMOS, ISP, HDMI, encoder, DMA, memory and storage as distinct nodes. Most physical connections remain UNKNOWN. The firmware components MAS, SLA and EX are distinct address domains; component names and identical code do not establish which EXPEED chip performs an image-processing task.

See [hardware/signal map](../diagrams/hardware.mmd) and [bounded software map](../diagrams/software.mmd).

A newly recovered local software slice loads address words from descriptor field +0x34, forwards the same vector through a selector dispatch and writes four words to q-selected software address families. Under valid objects, stable context and no overwrite, q=0 selects 20380218/20380310 groups and q=1 selects 20380228/20380320 groups, with the software bank term derived from J+4. This is address programming, not pixel access or physical-address proof.

The fixed view B2363298 contains descriptor/control information and is excluded as a frame body. Selection/retry fields are also control data. The real producer, image type, active address, width, stride, packing, valid precision, allocation/reuse and completion synchronization have not been established.

Original natural execution was observed at a bounded startup copy-request call in an unchanged fixed QEMU setup. That does not show the video path was reached, complete boot or recording. QEMU image-generation laws and completion conventions remain separate functional assumptions.
