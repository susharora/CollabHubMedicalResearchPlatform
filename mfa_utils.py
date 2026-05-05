"""
mfa_utils.py — Time-Based One-Time Password (TOTP) MFA for CollabHub
=====================================================================
Provides TOTP secret generation, code generation, and verification.

WHY TOTP (RFC 6238) over HOTP (RFC 4226):
  TOTP is time-based (30-second windows) so codes expire automatically,
  eliminating the need to track a counter state server-side. HOTP requires
  synchronised counter state between client and server, which is harder
  to manage and can drift. TOTP is the de-facto standard (Google Authenticator,
  Authy, Microsoft Authenticator all use TOTP).

WHY pyotp library not custom HMAC-SHA1:
  TOTP is HMAC-SHA1 over (key, time_counter) with specific truncation.
  pyotp is a well-audited, minimal implementation of RFC 6238. Writing
  custom TOTP risks subtle implementation bugs (endianness, truncation offset).
  Alternative: otpauth URI generation + qrcode for authenticator apps —
  considered for future; current requirement is screen display only.

CURRENT MODE (Development/Simulation):
  The TOTP code is displayed on screen, labelled as simulated.
  In production: replace display_code() with an SMS API call (Twilio, AWS SNS).
  The verification logic is identical in both modes.

SECURITY NOTE on 30-second window:
  pyotp.verify() accepts the current window AND one previous window (±30s)
  by default. This provides tolerance for clock skew between server and user
  device without materially weakening security.
"""

import pyotp
from typing import Tuple


def generate_totp_secret() -> str:
    """
    Generate a cryptographically secure base32 TOTP secret.
    WHY base32: RFC 6238 specifies base32-encoded secrets for TOTP.
    The output is 32 characters = 160 bits of entropy, more than sufficient
    for HMAC-SHA1 (160-bit key). Stored in users.totp_secret column.
    Alternative: base64 — rejected because the TOTP spec requires base32;
    using base64 would require a conversion on every code generation.
    """
    return pyotp.random_base32()


def get_current_code(totp_secret: str) -> str:
    """
    Generate the current 6-digit TOTP code for a given secret.
    The code is valid for the current 30-second window.
    Used in simulation mode to display the code on screen (replaces SMS send).
    """
    totp = pyotp.TOTP(totp_secret)
    return totp.now()


def verify_totp(totp_secret: str, entered_code: str) -> bool:
    """
    Verify a user-entered TOTP code against the stored secret.
    Returns True if the code matches the current OR immediately preceding
    window (±30 seconds tolerance for clock skew).

    WHY valid_window=1: Allows up to 30 seconds of clock drift between the
    CollabHub server and the user's device. Setting valid_window=0 would
    reject codes that are technically correct but entered at a window boundary.
    Setting valid_window=2 (90 seconds) weakens security unnecessarily.
    Alternative: Enforce strict window (valid_window=0) — rejected because
    it causes frustrating login failures at window boundaries.
    """
    if not entered_code or not totp_secret:
        return False
    totp = pyotp.TOTP(totp_secret)
    # valid_window=1 allows current + 1 previous 30s window
    return totp.verify(entered_code.strip(), valid_window=1)


def display_and_prompt_totp(totp_secret: str, mobile_number: str = None) -> str:
    """
    SIMULATION MODE: Display the current TOTP code on screen and prompt entry.
    Returns the code the user entered (caller must verify with verify_totp).

    In production: replace the print statement with an SMS API call and remove
    the code display. The prompt and verify logic remains unchanged.
    """
    code = get_current_code(totp_secret)
    mobile_display = mobile_number if mobile_number else "+XX XXXXXXXXXX (not set)"

    print(f"\n  ┌─────────────────────────────────────────────────────────────┐")
    print(f"  │  🔐 MULTI-FACTOR AUTHENTICATION                             │")
    print(f"  │                                                              │")
    print(f"  │  [SIMULATION MODE] Your one-time code:  {code}              │")
    print(f"  │  (Production: code sent to {mobile_display[:30]:<30})  │")
    print(f"  │  This code expires in 30 seconds.                           │")
    print(f"  └─────────────────────────────────────────────────────────────┘")

    entered = input("\n  ➤  Enter your 6-digit verification code: ").strip()
    return entered
