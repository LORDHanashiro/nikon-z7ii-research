# HDMI / N-Log boundary

Settings 0x126D → 0x16A5 and the recording-configuration field +0x46C form software control evidence. Settings 0x1688 / 0x16BF have conditional propagation. These are software identifiers/fields, not proven hardware register addresses.

The descriptor families behind D0 and Dp use different normal containers. Dp's own constructor at MAS 1030CADE reads its supplied configuration; the local layout can reach existing submission code under explicit gates without assuming D0==Dp. Active object identity and configuration timing remain UNKNOWN.

The validator at MAS 1047EC00 operates on a complete byte field with selected accepted values. A layout code, including 0xA, does not establish 10-bit sample precision. Software HDMI capability/configuration queries are not themselves EDID negotiation or actual pixel transport.

The N-Log processing stage, true high-depth buffer, CPU/DMA accessibility, connection/negotiation requirements and whether precision is retained before or after accessible memory remain UNKNOWN.
