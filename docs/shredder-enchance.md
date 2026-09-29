pre detect the drive before performing the operation:
if hdd:

NIST SP 800-88 Rev. 1 (Clear) — 1 Pass (Default): The modern, universally recognized default standard. Writes single-pass pseudorandom bytes or zeros.

DoD 5220.22-M — 3 Passes (Legacy Compliance Toggle): The legacy standard. Kept solely because older government/agency policies explicitly mandate "3-pass DoD wipes" by name.
if USB flash / SD / microSD:

Firmware purge is not implemented in the current backend. Probe SCSI UNMAP support, issue UNMAP only when the device advertises it, then run NIST Clear as a one-pass logical overwrite with readback verification. Record the UNMAP outcome separately; acceptance is not proof that wear-leveled NAND copies were physically erased. If the logical overwrite fails, recommend physical destruction and do not report sanitization success.
if nvme: 
same but worth telling them that it is unreliable better do drive sanitize
in the ui where u are providing the button of select algo add an i button to tell what it does like passes and when to use it