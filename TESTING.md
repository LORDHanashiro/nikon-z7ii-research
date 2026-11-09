# Publication validation boundary

Initial packaging validation used Python 3.12.3, NumPy 1.26.4, GCC 13.3.0 and Ghidra 12.2 PUBLIC APIs. These are tested local versions, not a claim of latest available versions.

* Six finite standard-library host/index tests passed.
* The self-authored C++20 synthetic recorder built with warnings treated as errors. A two-frame 130x37 run with short host writes passed the independent sample/CRC/sequence validator: 19,240 components, all 1,024 codes, and 4,810 samples in each low-two-bit class.
* RestorePublicAnnotations.java compiled against the installed Ghidra 12.2 API. It was not executed on an original firmware project during publication preparation.
* Initial packaging failures were preserved locally: missing EX node records (resolved with explicit UNKNOWN endpoints), two unclosed CSV handles (fixed), and an unavailable Ghidra conflict-handler constant (replaced after inspecting the actual API).

These checks validate selected software and publication properties. They do not establish actual camera pixels, valid N-Log precision, encoder support, DMA or card throughput, complete boot or internal recording. No test was skipped or removed to obtain a pass.

The current suite adds one publication-only gate test (seven tests total). Its local fake API responses cover an empty repository returning HTTP 409/404, rejection of other branches or tags, rejection of permission errors, and existing-main ancestry. These fake responses are not server observations. An actual newly created private GitHub repository independently returned HTTP 409 with empty branch/tag lists; the first attempted push stopped safely before data transfer and motivated the fix. Post-push checks verify both private branch heads and visibility.

Run `python3 -m unittest discover -s tests -v` for the small checks. The independent recorder reader additionally needs NumPy and a C++20 compiler. No firmware, camera, private capture or vendor binary is a test fixture in this repository.
