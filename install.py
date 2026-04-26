#!/usr/bin/env python3
"""
install.py — Cross-Platform Secure-Commit Installer
====================================================
One-time setup script. Run this once to wire Secure-Commit into your
Git repository as a pre-commit hook.

Usage:
    python install.py              # install the hook
    python install.py --uninstall  # remove the hook

Tested on: Windows 10/11 (Git Bash), macOS, Ubuntu Linux.
"""

import sys
import os
import shutil
import argparse
import subprocess
from pathlib import Path

# Force UTF-8 output so box-drawing characters work on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_ROOT   = Path(__file__).resolve().parent
VENV_DIR       = PROJECT_ROOT / ".venv"
REQUIREMENTS   = PROJECT_ROOT / "requirements.txt"
HOOK_SOURCE    = PROJECT_ROOT / "hooks" / "pre_commit.py"
GIT_HOOKS_DIR  = PROJECT_ROOT / ".git" / "hooks"
HOOK_DEST      = GIT_HOOKS_DIR / "pre-commit"   # No .py — Git requirement

# Platform-specific venv binary paths
IS_WINDOWS = sys.platform == "win32"
VENV_PYTHON = VENV_DIR / ("Scripts" if IS_WINDOWS else "bin") / (
    "python.exe" if IS_WINDOWS else "python"
)
VENV_PIP = VENV_DIR / ("Scripts" if IS_WINDOWS else "bin") / (
    "pip.exe" if IS_WINDOWS else "pip"
)


# ─────────────────────────────────────────────────────────────────────────────
#  COLOR OUTPUT (minimal ANSI — no external deps)
# ─────────────────────────────────────────────────────────────────────────────

def _ansi(code, text):
    if IS_WINDOWS:
        os.system("")   # Enable ANSI on Windows
    return f"\033[{code}m{text}\033[0m"

def ok(msg):   print(f"  \033[92m✓\033[0m  {msg}")
def err(msg):  print(f"  \033[91m✗\033[0m  {msg}")
def info(msg): print(f"  \033[94m→\033[0m  {msg}")
def warn(msg): print(f"  \033[93m⚠\033[0m  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
#  INSTALLER STEPS
# ─────────────────────────────────────────────────────────────────────────────

def check_python_version():
    """Ensure Python 3.8+ is being used."""
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        err(f"Python 3.8+ required. Found: {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor}.{sys.version_info.micro} detected")


def check_git_hooks_dir():
    """Ensure we are inside a Git repository with a hooks directory."""
    if not (PROJECT_ROOT / ".git").exists():
        err("No .git directory found. Run this installer from inside a Git repository.")
        sys.exit(1)

    GIT_HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    ok(f"Git hooks directory confirmed: {GIT_HOOKS_DIR}")


def create_virtual_environment():
    """Create .venv if it doesn't already exist."""
    if VENV_DIR.exists():
        ok(f"Virtual environment already exists: {VENV_DIR}")
        return

    info("Creating virtual environment (.venv)...")
    result = subprocess.run(
        [sys.executable, "-m", "venv", str(VENV_DIR)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        err(f"Failed to create virtual environment:\n{result.stderr}")
        sys.exit(1)

    ok(f"Virtual environment created: {VENV_DIR}")


def install_dependencies():
    """Install gitpython and pyyaml into .venv."""
    info("Installing dependencies into .venv...")

    if not REQUIREMENTS.exists():
        err(f"requirements.txt not found at: {REQUIREMENTS}")
        sys.exit(1)

    result = subprocess.run(
        [str(VENV_PIP), "install", "-r", str(REQUIREMENTS), "--quiet"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Try without pinned versions if exact version fails (e.g. new Python)
        warn("Pinned install failed. Trying unpinned versions...")
        result = subprocess.run(
            [str(VENV_PIP), "install", "gitpython", "pyyaml", "--quiet"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            err(f"Dependency installation failed:\n{result.stderr}")
            sys.exit(1)

    ok("Dependencies installed: gitpython, pyyaml")


def install_hook():
    """
    Write the pre-commit hook file to .git/hooks/pre-commit.

    The hook file is a small Python wrapper that:
      1. Activates the .venv Python interpreter
      2. Adds the project root to sys.path
      3. Calls hooks/pre_commit.py main()

    This approach ensures the hook always uses the correct Python + dependencies
    regardless of what Python is active in the developer's shell.
    """
    if not HOOK_SOURCE.exists():
        err(f"Hook source not found: {HOOK_SOURCE}")
        sys.exit(1)

    # Determine the correct Python interpreter path (absolute, venv)
    python_path = str(VENV_PYTHON).replace("\\", "/")   # Git Bash uses forward slashes
    project_path = str(PROJECT_ROOT).replace("\\", "/")

    # Write a thin wrapper script as the actual hook file
    hook_content = f"""#!/usr/bin/env python
# Secure-Commit Pre-Commit Hook
# Auto-generated by install.py — do not edit manually.
# To reinstall: python install.py
import sys
import subprocess
from pathlib import Path

# Use the venv Python so gitpython/pyyaml are available
venv_python = Path(r"{VENV_PYTHON}")
hook_script  = Path(r"{HOOK_SOURCE}")

if not venv_python.exists():
    print("  [SECURE-COMMIT] .venv not found. Run: python install.py")
    sys.exit(1)

result = subprocess.run(
    [str(venv_python), str(hook_script)],
    cwd=r"{PROJECT_ROOT}",
)
sys.exit(result.returncode)
"""

    HOOK_DEST.write_text(hook_content, encoding="utf-8")

    # On Linux/macOS: set executable bit (not needed on Windows)
    if not IS_WINDOWS:
        HOOK_DEST.chmod(0o755)
        ok("Hook file made executable (chmod +x)")

    ok(f"Hook installed: {HOOK_DEST}")


def validate_installation():
    """Quick sanity check — confirm the hook file exists and is non-empty."""
    if not HOOK_DEST.exists():
        err("Validation failed: hook file not found after installation.")
        sys.exit(1)

    size = HOOK_DEST.stat().st_size
    if size < 50:
        err(f"Validation failed: hook file is suspiciously small ({size} bytes).")
        sys.exit(1)

    ok(f"Hook file validated ({size} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
#  UNINSTALLER
# ─────────────────────────────────────────────────────────────────────────────

def uninstall():
    """Remove the pre-commit hook from .git/hooks/."""
    if HOOK_DEST.exists():
        HOOK_DEST.unlink()
        ok(f"Hook removed: {HOOK_DEST}")
    else:
        warn("Hook was not installed — nothing to remove.")

    print()
    info("Uninstall complete. Your code, .venv, and policies are untouched.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Secure-Commit Installer — wires the pre-commit hook into .git/hooks/"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the Secure-Commit hook from .git/hooks/",
    )
    args = parser.parse_args()

    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║    SECURE-COMMIT  |  INSTALLER  v1.0     ║")
    print("  ╚══════════════════════════════════════════╝")
    print()

    if args.uninstall:
        uninstall()
        return

    info("Starting installation...")
    print()

    check_python_version()
    check_git_hooks_dir()
    create_virtual_environment()
    install_dependencies()
    install_hook()
    validate_installation()

    print()
    print("  ══════════════════════════════════════════════")
    ok("Installation complete!")
    info("Secure-Commit will now run automatically on every 'git commit'.")
    print("  ══════════════════════════════════════════════")
    print()


if __name__ == "__main__":
    main()
