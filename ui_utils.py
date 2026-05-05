"""
ui_utils.py — Terminal UI Helpers for CollabHub
================================================
Provides all terminal input/output primitives used across role modules.
Centralising UI functions ensures consistent formatting, error messaging,
and input validation throughout the application.

DESIGN PRINCIPLES:
  - All numerical menu choices return -1 for invalid input (never raise)
    so role menus can loop gracefully without try/except at every call site.
  - Error messages are displayed with a ✖ prefix and are descriptive,
    identifying the problem and (where possible) the remediation.
  - The choose() function is the only entry point for numerical menu input,
    ensuring consistent validation in one place.

WHY NOT curses/rich/click:
  - curses: adds terminal capability dependency; not portable to Windows
  - rich: external dependency not needed for a security prototype
  - click: designed for CLI tools, not interactive menu-driven applications
  Alternative: Prompt Toolkit — provides readline-like editing and coloured
  prompts; rejected as over-engineering for a security reference system.
"""
import os
import sys


BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║          COLLAB HUB — Secure Clinical Research Collaboration Platform        ║
║                                                                              ║
║  Enables cross-border secure clinical research collaboration without         ║
║  exposing sensitive patient information between multiple independent         ║
║  parties (hospitals, research organisations and auditors).                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

SEPARATOR = "─" * 78


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print(BANNER)


def print_sep():
    print(SEPARATOR)


def print_header(title: str):
    print()
    print_sep()
    print(f"  {title}")
    print_sep()


def pause(msg: str = "Press [Enter] to continue..."):
    input(f"\n  {msg}")


def info(msg: str):
    print(f"\n  ℹ  {msg}")


def success(msg: str):
    print(f"\n  ✔  {msg}")


def error(msg: str):
    print(f"\n  ✖  {msg}")


def warn(msg: str):
    print(f"\n  ⚠  {msg}")


def prompt(msg: str) -> str:
    return input(f"\n  ➤  {msg}: ").strip()


def prompt_password(msg: str = "Password") -> str:
    import getpass
    return getpass.getpass(f"\n  ➤  {msg}: ")


def choose(options: list, prompt_msg: str = "Select option") -> int:
    """Display numbered options and return chosen index (1-based).
    Returns -1 if invalid.
    """
    print()
    for i, opt in enumerate(options, 1):
        print(f"     {i}. {opt}")
    val = prompt(prompt_msg)
    try:
        choice = int(val)
        if 1 <= choice <= len(options):
            return choice
        error(f"Please enter a number between 1 and {len(options)}.")
        return -1
    except ValueError:
        error("Invalid input. Please enter a number.")
        return -1


def confirm_yn(msg: str) -> bool:
    val = prompt(f"{msg} [Y/N]")
    return val.lower() in ("y", "yes")


def print_table(headers: list, rows: list, widths: list = None):
    """Simple table printer."""
    if not widths:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print()
    print(fmt.format(*headers))
    print("  " + "  ".join("─" * w for w in widths))
    for row in rows:
        cells = [str(row[i]) if i < len(row) else "" for i in range(len(headers))]
        print(fmt.format(*cells))
    print()
