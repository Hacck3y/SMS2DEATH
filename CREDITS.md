# Credits

This repository is a packaged, rebranded release built on top of other people's research. The
findings, the original proof of concept, and the recovery procedure are not the work of this
repository's maintainer.

## Original research

**Mark B** — discovery and analysis of the unchecked cast in `WapPushOverSms.decodeWapPdu()`,
the original report to the Android & Devices VRP (5 May 2026), the public writeup
(29 Oct 2026), and the upstream proof-of-concept application.

- Upstream repository: <https://github.com/MarkBlah/smsofdeath>
- Writeup: <https://smsofdeath.com/>

The payload, the vulnerable code path, and the analysis in this README originate there and are
reproduced in accordance with the upstream Apache License 2.0.

## Recovery procedure

**[@sakisdog](https://github.com/sakisdog)** — documented the ADB-based recovery that deletes the
poison rows in `content://sms/raw` and breaks the boot loop without a factory reset, after
independently reproducing the reboot loop on Android 12.

- Original report: upstream issue #2 — <https://github.com/MarkBlah/smsofdeath/issues/2>

## This release

**Hacck3y** — packaging and release work in this repository:

- Rebranded application (application ID `com.hacck3y.sms2death`, version 2.0)
- Redesigned on-device UI: dark theme, structured sections, in-app run log, PDU display and
  clipboard copy
- Live radio monitor (service-state and call-state transitions) so the crash can be observed
  on-device without a computer
- Documentation: README, disclaimer, and screenshots

## Platform acknowledgements

The Australian Communications and Media Authority (ACMA), Telstra, and the Department of
Prime Minister and Cabinet publish the emergency-call obligations discussed in this README.
Links are in the [References](README.md#references) section.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
