USB LOCKER PRO
==============

LATEST PATCH: THE INTERRUPTED-SWAP BUG (IMPORTANT)
-------------------------------------------------------
Symptom: a .tmp file left on the USB drive, the finished .usbvl left on the
other drive, and the 'Unlocked' folder never deleted.

Cause: when building the vault at another location, the final step (copying
the finished vault from that drive onto the USB) used a copy routine that
reported NO progress at all. On a multi-GB vault going onto a slow USB
drive, that step can take many minutes while the progress bar sits frozen at
100% - looking exactly like a hung application. Force-closing it there left
the swap half-done.

Fixed:
  1. That copy is now chunked and reports live progress, so you can see it
     working instead of guessing.
  2. The progress bar now shows a PHASE LABEL naming what's happening right
     now, in plain words: "Encrypting your files...", "Checking the new
     vault is complete and correct...", "Removing the old vault to make
     room...", "Copying the vault onto the USB drive (this is the slow
     part)...", "Final check of the vault on the USB drive...", "Securely
     erasing the unlocked copy...". The bar restarts per phase, so later
     stages no longer sit at a misleading 100%.
  3. The bar now shows an exact percentage alongside size, speed and time
     left.
  4. The vault copied onto the USB is now verified ON THE USB before the
     build copy elsewhere is deleted. Previously the build copy was removed
     after only a size comparison.
  5. If the copy fails or is interrupted, the app no longer discards
     anything. It tells you exactly where the complete, verified vault
     still is and how to finish the copy by hand.
  6. A stranded .tmp from an interrupted swap is now detected on launch and
     explained on the main screen, instead of silently occupying space.
  7. Any stale .tmp is cleared before a new swap starts.

IF YOU ARE STUCK RIGHT NOW (leftover .tmp / vault on the wrong drive)
-------------------------------------------------------------------------
Your data is not lost. Do this, in order:

  1. Find the rebuild file on your other drive. It is named
     USBLockerPro_rebuild_<numbers>.usbvl - this is your COMPLETE vault.
  2. On the USB drive, delete the leftover partial file at
     <USB>\.USBLocker\vault.tmp if it exists.
  3. Copy the rebuild file onto the USB as:
         <USB>\.USBLocker\vault.usbvl
     (rename it to exactly vault.usbvl).
  4. Open the app, select the drive, and click "Verify Vault". Enter your
     password. Only if it verifies successfully, delete the rebuild file
     from the other drive and the leftover 'Unlocked' folder.

Do not delete the rebuild file until step 4 passes.


LATEST PATCH: CHOOSE WHERE TO WORK (STORAGE MANAGEMENT)
------------------------------------------------------------
Unlock and Lock Now now ask ONCE per app session: work directly on the USB
drive (default, same as before), or pick a different folder instead (e.g.
your computer's SSD)? Your answer is remembered for the rest of that
session, so you're not asked again on every single unlock/lock - only once,
unless you restart the app.

Why you might want this: building/reading directly on a slow USB flash
drive the whole time is slower than working on a fast local disk and only
touching the USB for the compact final copy. Picking a different location
also means the USB drive itself stays less full while you're actively
editing a large vault's worth of files.

This required a real fix underneath: crash-recovery ("Recover Unsaved
Session") used to only ever look for a leftover working folder ON the USB
itself. Now that the working folder can legitimately be somewhere else, the
app writes a small marker file (.USBLocker/working_location.txt) recording
exactly where it unlocked to, and crash-recovery reads that instead of
assuming - tested end-to-end (unlock to a different drive, simulate a
crash, confirm recovery still finds and saves it correctly from the right
place). The marker is cleared automatically once you Lock Now or recover
successfully.

LATEST PATCH: RUNNING OUT OF SPACE NEAR A FULL DRIVE
------------------------------------------------------------
Real bug, not a tuning issue: saving changes ("Lock Now") used to build the
UPDATED vault right next to the OLD one, then swap them - which needs
roughly 2x your data's size in free space (old vault + new vault, both
briefly present, on top of the already-unlocked plaintext copy). On a
drive where the vault is a large fraction of total capacity, that's
impossible by design, no matter how well-optimized the encryption itself
is.

Fixed, in three parts:

  1. Lock Now now asks SAVE / DISCARD / CANCEL instead of just yes/no.
     Choosing DISCARD keeps the vault exactly as it was and just wipes the
     temporary folder - no re-encryption, so it can't run out of space and
     is instant.
  2. Before saving, the app checks whether there's actually room to build
     the updated vault. If there's enough free space, it uses the normal
     fast path (unchanged). If not, it tells you exactly how much is
     needed vs. free, and - only if it WOULD fit once the old vault is
     removed - offers to build the new vault on another drive first, fully
     verify it there, and only then delete the old vault and move the
     verified new one onto the USB. If it genuinely wouldn't fit even
     after removing the old vault, it says so plainly instead of trying
     and failing halfway through.
  3. The same free-space check (and the same safe build-elsewhere-first
     fallback) now also runs before creating a brand-new vault, not just
     on Lock Now.

The old vault is never deleted until a complete, cryptographically
VERIFIED replacement already exists somewhere safe - so a failure at any
point during this process leaves you with either the original vault intact
or a confirmed-good new one, never a half-written one.

LATEST PATCH: THE "IT STOPS" / IMPOSSIBLE-SPEED ISSUE
-----------------------------------------------------------
If you saw a speed reading way faster than any real USB drive can do
(hundreds of MB/s on a flash pendrive), followed by what looked like a
freeze - that's Windows write-behind caching, not the app hanging. Writes
were going into RAM first (reported instantly, looks blazing fast), and
only actually reaching the slow flash drive later in the background. Once
that RAM buffer filled up, everything had to block and wait for the real,
much slower hardware to catch up - which looked like the process stopping.

Fixed: the app now forces a real write-to-hardware (fsync) every 48MB
instead of letting Windows silently buffer an unbounded backlog. This
caps how long any single "catch up to the real drive" pause can be, and
makes the speed/ETA reading honest - it'll now reflect what the USB drive
can actually sustain, not a temporary RAM-speed burst.

LATEST PATCH: LARGE DATA (30GB+) - HEADER FORMAT REWRITE
--------------------------------------------------------------
This is a real fix, not just a tuning tweak. The vault header used to
record the exact byte offset/length of EVERY 1MB chunk as text. For 30GB
that's ~30,000 chunks trying to cram into a fixed 16KB header block - it
would encrypt the entire 30GB (taking a long time) and then fail right at
the end with "too many files for this prototype's fixed header size."

Fixed: the header (format v4, magic "USBVL04") now stores only each file's
path and total size - chunk boundaries are recomputed mathematically on
read instead of being stored. A 50MB multi-chunk file's header entry is now
about 50 bytes, regardless of how large the file actually is. Also bumped
the chunk size from 1 MiB to 4 MiB (fewer, bigger writes = less overhead).
There's still a fast upfront size check before encryption starts, so an
unreasonable file COUNT (tens of thousands of tiny files) fails in under a
second with a clear message, instead of after hours of work.

Your EXISTING vaults (format v3) still open and work exactly as before -
nothing is lost. The first time you click "Lock Now" on one, it's silently
rewritten in the new compact format automatically.

Also added: a live speed + time-remaining readout under the progress bar
during any large operation, so you can actually see whether it's moving
and roughly how long is left.

ABOUT THE HEAT
----------------
Some of what you're feeling is genuinely unavoidable, not a bug: writing
30GB to a USB flash drive means sustained heavy write activity for
(realistically) tens of minutes, and flash controllers get warm under
that regardless of which program is doing the writing - Windows' own
"Copy" dialog or 7-Zip would produce similar heat on the same drive. The
header fix above removes a real bottleneck/failure on top of that, but it
won't make physics go away. Practical notes:
  - Cheap/older USB 2.0 drives run hotter and slower under sustained
    writes than a decent USB 3.0/3.1 flash drive - if this is a recurring
    workload, a better-quality drive genuinely helps.
  - A drive that's uncomfortably hot to touch, or that starts slowing
    down partway through a large transfer, may be thermal-throttling -
    that's the controller protecting itself, and is a hardware
    characteristic, not something software controls.
  - If a specific drive gets unusually hot even for a small transfer, or
    the heat doesn't go away when it's idle, that can be a sign of a
    failing drive worth retiring - worth keeping an eye on separately
    from normal warm-during-heavy-use behavior.

LATEST PATCH: SURVIVING A CRASH / FORCE-CLOSE / SUDDEN SHUTDOWN
------------------------------------------------------------------
Previously, if the app closed abnormally (crash, Task Manager "End Task",
the USB pulled out early, a power loss) while a vault was unlocked, the
decrypted "Unlocked" folder was just left sitting on the USB, unencrypted,
with no automatic cleanup. Three layers now handle this:

  1. Closing the window normally (the X button) still asks to save + wipe,
     same as before - now it also tells you plainly what happens if you
     say no.
  2. NEW - "Recover Unsaved Session": if you open the app on a drive and it
     finds an "Unlocked" folder already sitting there from a run that
     didn't close cleanly, it will NOT silently decrypt over it. Instead
     every other vault button is disabled and a new "Recover Unsaved
     Session" button lights up. Click it, enter your password, and it
     saves whatever was in that leftover folder into the encrypted vault
     (same as a normal Lock Now) and wipes the temporary copy. This is what
     actually covers a crash, a force-kill, or a power loss, because it
     runs on the NEXT launch - after any of those, nothing can run code
     before the fact.
  3. Best-effort: the app also tries to auto-save-and-wipe on Ctrl+C or a
     graceful termination signal, as an extra layer on top of the two
     above. This only works when the process gets a chance to run Python
     code before exiting, so it does NOT help with a power loss or "End
     Task" - be clear-eyed that #2 is the real safety net for those.

Nothing can run code after a power cut or a hard kill, by definition - so
"erase it before the issue happens" isn't physically possible for those
cases. What IS possible, and what this patch does, is guarantee it gets
found and cleaned up automatically the next time the app runs on that
drive, rather than sitting there silently.

LATEST PATCH: RECOVERY KEY DISPLAY
-------------------------------------
- Create now re-reads the vault header back from disk right after writing
  it and confirms the recovery-key count actually matches what was
  generated - any mismatch now raises a clear, loud error immediately
  instead of silently moving on.
- Unlock now explicitly states your recovery-key count in the status line
  the instant you're in, instead of leaving it to a possibly-stale label.
- Lock Now's success message now states your recovery-key count directly
  (locking never changes it - now it says so).
- Reworded the "Generate recovery keys now?" prompt at creation to make it
  much harder to accidentally click through as "No" and end up with zero
  keys without realizing it.

WHAT'S NEW IN THIS REVISION
----------------------------
1. "Forgot Password?" is now DISABLED (and explains why) whenever the vault
   has zero unused recovery keys - you won't get a confusing failure, you
   get a clear "not available because no recovery keys exist" message up
   front, and the button greys out on the main screen too.
2. When you DO successfully reset your password with a recovery key, the
   app now tells you how many recovery keys you have left and offers to
   generate a brand-new full set right then, so you don't slowly run out.
   A "Manage Recovery Keys..." button also lets you top up to a fresh set
   of 5 at any time (old unused keys are retired when you do).
3. Basic brute-force slowdown: after 3 wrong password/recovery-key
   attempts on a given vault in one app session, further attempts are
   blocked for a short, growing cooldown (starts at 20s, caps at 5 min).
4. New passwords are checked against a rough strength estimate at
   creation time; a clearly weak password now gets a warning (with a
   chance to change your mind) instead of being silently accepted.
5. Visual refresh: actions are grouped into Vault / Recovery / Maintenance
   sections, with a status line that also shows your remaining recovery
   key count.
6. Unlock now checks free space FIRST: if the USB drive doesn't have
   enough room to hold the decrypted files, it tells you how much is
   needed vs. how much is free, then lets you pick another location (your
   laptop, another drive) to unlock into instead - rather than failing
   partway through a decrypt. "Lock Now" still works normally afterward
   and saves back into the vault on the USB either way.
7. FIXED: a bug where the app could silently create a brand-new vault
   (new password, new recovery keys) on its own, without you clicking
   anything - wiping out your real vault's recovery keys in the process.
   This happened because opening the app or reselecting your drive used
   to auto-run "Create" whenever it didn't immediately see a vault, and a
   freshly-inserted USB can take a moment to finish mounting, so that
   check could misfire. Now: auto-unlock (asking for your password) can
   still happen automatically since it's harmless, but "Create / Replace
   Vault" NEVER runs unless you click that button yourself.
8. FIXED: while a vault is unlocked, "Create NEW Vault", "Forgot
   Password?", "Manage Recovery Keys...", "Verify Vault", and "Reset App"
   are now all disabled (and the drive selector locks too). Previously
   these stayed clickable during an active session, which made it very
   easy to reach for "Create / Replace Vault" out of habit instead of
   "Lock Now" - silently building a brand-new vault (new password, and
   only new recovery keys if you said yes to that popup) on top of the
   real one, which is what was destroying people's recovery keys. The
   button is also relabeled "Create NEW Vault (erases old one)" and now
   requires typing REPLACE to confirm when a vault already exists, as a
   second safety net.


A Windows desktop college-project prototype for protecting files on a USB
drive: encrypted vault, one main password, up to 5 one-time recovery keys
for "Forgot Password", a Reset-App wipe, and a mutable unlock/lock cycle.

WHAT CHANGED IN THIS REVISION (per your feedback)
---------------------------------------------------
1. FACE LOCK REMOVED. No webcam, no OpenCV dependency. Simpler and one
   less thing that can fail to install.

2. "Create / Replace Vault" IS NO LONGER DISABLED once a vault exists.
   It's always clickable - it asks you to confirm before replacing an
   existing vault, same as before, it just isn't locked out anymore.

3. "FORGOT PASSWORD" NOW WORKS LIKE A NORMAL APP:
   At setup you can generate up to 5 RECOVERY KEYS - random codes like
   "K3F9X-7QPLD-2MZRT-VVBCA", shown to you ONCE in a popup, the same idea
   as the backup codes Google/GitHub give you for 2FA. If you forget your
   password:
     - Click "Forgot Password?"
     - Enter one recovery key
     - Set a BRAND NEW main password
   That recovery key is then permanently spent (single-use) and cannot be
   reused - exactly like a normal app's backup codes.

4. THE VAULT IS NOW MUTABLE. Previously, once created, the vault could
   only be read, never changed. Now:
     - "Unlock" decrypts your files into an "Unlocked" folder ON THE USB
       DRIVE ITSELF (not a hidden temp folder on your laptop) and opens it
       in File Explorer.
     - Use it like a completely normal folder: open files, edit them, add
       new files, delete files you don't want anymore.
     - Click "Lock Now" and it SAVES whatever is currently in that folder
       back into the encrypted vault (re-encrypting it), then securely
       wipes the temporary plaintext copy. Your password(s)/recovery keys
       are untouched - you don't need to re-enter anything.

5. "Copy Unlocked Files To..." - new button, only enabled while a vault is
   unlocked. Explicitly copies the currently-unlocked files to a folder you
   choose - your laptop, another drive, wherever. This is for when you
   actually want a second copy elsewhere; it does not affect the vault.

WHY FILES OPEN IN A FOLDER ON THE USB (NOT YOUR LAPTOP)
------------------------------------------------------------
Earlier this decrypted into a hidden temp folder on your laptop
(C:\Users\...\AppData\Local\Temp\...), which is confusing and also means
the plaintext ends up on a computer you may not own. Now it decrypts into
"Unlocked" right there on your pen drive, so you're always working with
your pendrive's own files, on whichever computer you're using. The
trade-off: while unlocked, anyone with physical access to that computer AND
the drive could read those files - always click "Lock Now" before you
remove the drive or walk away. If you genuinely want a copy that lives on
your laptop, use "Copy Unlocked Files To..." for that on purpose.

WHAT "SECURELY WIPE" MEANS
-------------------------------
A normal delete just marks a file's disk space as "free" - the actual
bytes are often still sitting there and recoverable with undelete software
until something else happens to overwrite that space. "Securely wipe"
instead overwrites every byte of the file with zeros BEFORE deleting it,
so there's nothing meaningful left for a recovery tool to find. This app
uses it for the "Unlocked" folder on Lock Now, for "Reset App", and for the
"Securely Wipe a Folder..." button (for any other decrypted copy you made,
e.g. via "Copy Unlocked Files To..."). Caveat: on SSD/flash storage the
controller can silently remap blocks internally, so even this is
best-effort, not an absolute physical guarantee.

SECURITY DESIGN
----------------
- AES-256-GCM authenticated encryption for file contents.
- A random 256-bit master key per vault encrypts the actual files - never a
  password directly.
- The master key is key-wrapped once per password (main + up to 5 recovery
  keys), each with Argon2id + its own random salt and nonce. Any one
  password/key independently recovers the same master key.
- Random nonce per encrypted chunk; associated data binds each chunk to its
  file path, chunk number, and plaintext length.
- No password or recovery key is stored in plaintext, anywhere.
- Wrong passwords and tampered ciphertext fail authentication.

WHAT "LOCKED" MEANS
--------------------
The protected data is stored in:

    USB:\.USBLocker\vault.usbvl

The vault contents are ciphertext while locked. Windows cannot open the
protected photos/videos/documents as their original file types.

This is NOT a full-disk encryption driver. It does not make the whole USB
invisible to Windows, and it cannot control copies, screenshots, OS caches,
pagefile data, or malware on the host PC.

INSTALL (running from source with Python)
------------------------------------------
1. Install Python 3.11 or newer on Windows.
2. Open Command Prompt in this project folder.
3. Run:

    python -m pip install -r requirements.txt

4. Run:

    python usb_locker_pro.py

   or double-click run_usb_locker_pro.bat.

MAKING IT TRULY PORTABLE (build once, run anywhere - no Python needed)
--------------------------------------------------------------------------
1. On your own PC, with Python installed, double-click
   build_portable_exe.bat in this folder. It installs PyInstaller and the
   app's dependencies, then builds dist\USBLockerPro.exe.
2. Copy dist\USBLockerPro.exe onto the USB drive itself.
3. On any Windows PC, plug in the drive and double-click USBLockerPro.exe
   directly from the drive. No Python installation is required on that PC.
   The app auto-detects it's running from that drive and offers it first.

FIRST RUN ON A DRIVE (creating a vault)
------------------------------------------
1. Insert the USB and launch the app.
2. It detects no vault exists and prompts you automatically:
     a. Select the folder to protect.
     b. Create a strong main password (12+ characters).
     c. Optionally generate 5 recovery keys - SAVE THEM SOMEWHERE SAFE,
        they're shown only once.
3. Wait until encryption finishes, then use "Verify Vault" before deleting
   any original, unencrypted copies yourself.

EVERY RUN AFTER THAT (unlocking, editing, locking again)
-------------------------------------------------------------
1. Insert the USB and launch the app - it asks for your password
   automatically.
2. Your files open in the "Unlocked" folder on the USB drive.
3. Add, edit, or delete files in there freely.
4. Click "Lock Now" when finished - your changes are saved back into the
   encrypted vault and the temporary plaintext copy is wiped.

FORGOT YOUR PASSWORD?
----------------------
Click "Forgot Password?", enter one of your recovery keys, and set a new
main password. That recovery key is then spent and can't be reused. If you
never generated recovery keys and you forget your password, the vault
cannot be recovered - "Reset App" (below) is the only remaining option, and
it still requires a working password/key to run.

RESET APP
---------
Wipes the vault on a drive so you can start fresh. Requires your main
password or any unused recovery key first - a wrong one changes nothing.

IMPORTANT
---------
- Forgetting your password with no recovery keys left means the vault
  cannot be recovered by this app.
- Keep at least one backup of important data, separate from the vault.
- Do not remove the USB while an operation is running.
- If the computer may be infected with malware, do not enter your
  password/recovery key on it.
