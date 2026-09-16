# USB Locker Pro

A portable, password-protected encrypted vault for a USB drive. Carry the
app on the pendrive itself, plug it into any Windows PC, and unlock your
files there - no install required on the host computer.

- **AES-256-GCM** encryption, **Argon2id** password hashing
- One main password **+ up to 5 single-use recovery keys** ("forgot password" that actually works)
- Vault is **mutable** - unlock into an "Unlocked" folder right on the USB drive, edit files normally, "Lock Now" re-encrypts your changes
- Automatically recovers a leftover session if the app was force-closed or crashed
- No cloud, no telemetry, no account - everything stays on the drive

> Full technical details, threat model, and every changelog entry are in
> [`README.txt`](README.txt).

## Download

Grab the latest `USBLockerPro.exe` from the **[Releases](../../releases)**
page. Copy it onto your USB drive and double-click it from there - on any
Windows PC.

### ⚠️ Read this before your first download

`USBLockerPro.exe` is **not code-signed** (a signing certificate costs
money and isn't something a personal/college project normally has). That
means Windows will not recognize it as coming from a "known" publisher,
and you should expect one of these on first run:

| What you'll see | What to do |
|---|---|
| Blue "Windows protected your PC" (SmartScreen) | Click **More info**, then **Run anyway** |
| **Smart App Control** silently blocks it, no override offered | Settings → Privacy & security → Windows Security → App & browser control → Smart App Control → **Off** (this is a one-way toggle - see note below) |
| Antivirus flags/quarantines it | Most likely a false positive from an unsigned/uncommon exe - allow it if you trust the source, or build from source yourself instead (see below) |

This is completely normal for small, independent, unsigned Windows tools -
it is *not* a sign the file is malicious, just that Windows can't vouch for
it yet. If you'd rather not run an exe from a stranger's download page at
all, build it yourself from source (below) so you know exactly what went
into it.

**Smart App Control note:** once you turn it off, Windows currently does
not let you turn it back on without a full OS reset/reinstall. That's a
real trade-off, not a bug in this app - be sure before you disable it.

## Build it yourself instead

If you don't want to trust a pre-built binary:

```
git clone <this repo>
cd usb-locker-pro
python -m pip install -r requirements.txt
build_portable_exe.bat
```

`dist\USBLockerPro.exe` is now yours, built entirely on your own machine.
This repo also includes a [GitHub Actions workflow](.github/workflows/release.yml)
that does the same build on GitHub's own servers for every tagged release -
you can compare its build log against what you get locally if you want to
verify nothing was tampered with.

## Run from source (no exe at all)

```
python -m pip install -r requirements.txt
python usb_locker_pro.py
```

Requires Python 3.11+ on Windows.

## Project status

This started as a college project and is offered as-is. It is **not** a
substitute for full-disk encryption or a commercially audited security
product - read the "SECURITY DESIGN" and "IMPORTANT" sections of
[`README.txt`](README.txt) before relying on it for anything sensitive.

## License

MIT License - see [`LICENSE`](LICENSE). In short: anyone can use, modify,
and redistribute this freely, including commercially, as long as the
copyright notice stays attached. No warranty is provided.
