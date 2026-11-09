# H.264 capability remains UNKNOWN

Recovered event, configuration, address-record and software-port relationships do not establish the complete encoder hardware contract. Profile/level interpretations and SPS-like parameters are INFERRED where supported by comparisons; container widths, defaults and HDMI output capability are insufficient evidence of encoder precision.

Neither genuine 10-bit encoding support nor silicon incapability has been proved. Required evidence includes actual input packing/valid bits, encode versus decode direction, active DMA/ownership, output bitstream syntax and original execution under the intended mode.

The original internal recording default is not used to rule out silicon capability. Conversely, a format enum or a wider coefficient/storage field is not used to claim High 10 support. The public indices are navigation aids, not an implemented encoder patch.
