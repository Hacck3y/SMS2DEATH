# Disclaimer

**Read this before you download, build, or run anything in this repository.**

## What this is

SMS2DEATH is a **working proof-of-concept exploit**. It is a weaponised tool that can remotely
disrupt — and in documented cases effectively brick — mobile phones by killing
`com.android.phone` on the target handset. It does this without any interaction from the victim,
and while it is in effect the target device may be unable to place a call to emergency services
(Triple Zero / 000 / 911 / 112).

It is published strictly for **security research, education, and defensive testing**.

## What you are allowed to do

- Run it against **devices you own**.
- Run it against devices you have **explicit, written authorisation** to test.
- Study the source, the payload, and the accompanying writeup.
- Use it to verify that your own devices and fleet are patched.

## What you are not allowed to do

- Run it against **anyone else's device**, for any reason.
- Send the payload to a friend, family member, colleague, or anyone who has not authorised you
  in writing.
- Use it in a way that interferes with a person's ability to reach emergency services.

In Australia, deliberately interfering with a person's ability to reach `000` is a serious
criminal offence, and using a carriage service to menace, harass, or cause offence is an offence
under the Criminal Code and the Telecommunications Act. Equivalent law exists in most other
countries (for example the UK Computer Misuse Act, the US CFAA, and similar national
frameworks). Penalties include imprisonment.

## The "authorised testing only" rule is not a formality

An authorisation must come from someone who actually has the authority to grant it — the owner
of the device and, where the device is on a carrier network, permission that covers a remote
telephony test. "I was curious", "it was my friend's phone", and "I wanted to see what happened"
are not authorisation, and neither is a bug-bounty program that does not cover this target.

## Risk to the target device

- Active calls are dropped, including emergency calls.
- The device can enter a reboot loop that requires a computer and ADB to break
  (see the recovery section of the README). A non-technical user may be forced into a factory
  reset, losing data.
- A device that can no longer reach emergency services can be **blocked from carrier service**
  under the Telecommunications (Emergency Call Service) Determination.
- Carrier redelivery of the message can re-crash the device repeatedly for days.

## No warranty, no liability

The software is provided **"as is"**, without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a particular
purpose, and non-infringement. In no event shall the authors or copyright holders be liable for
any claim, damages, or other liability, whether in an action of contract, tort, or otherwise,
arising from, out of, or in connection with the software or the use or other dealings in the
software.

By downloading the APK or cloning the source you accept **full responsibility** for what you do
with it.

## License

Apache License 2.0 — see [LICENSE](LICENSE). The upstream research project by Mark B is licensed
under the same terms; see [CREDITS.md](CREDITS.md).
