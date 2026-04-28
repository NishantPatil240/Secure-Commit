#!/usr/bin/env python3
"""
install.py — Cross-Platform Secure-Commit Installer
====================================================
One-time setup script. Run this once to wire Secure-Commit into your
Git repository as a pre-commit hook.

Usage:
    Windows:
        python install.py              # install the hook
        python install.py --uninstall  # remove the hook
    Linux / macOS:
        python3 install.py
        python3 install.py --uninstall

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

# ── Framework root: where install.py (and engine/, hooks/, etc.) live ──────────
# This is always the secure-commit folder itself.
PROJECT_ROOT  = Path(__file__).resolve().parent
VENV_DIR      = PROJECT_ROOT / ".venv"
REQUIREMENTS  = PROJECT_ROOT / "requirements.txt"
HOOK_SOURCE   = PROJECT_ROOT / "hooks" / "pre_commit.py"

# ── Target Git root: discovered at runtime via git rev-parse ─────────────────
# This is the TOP-LEVEL project that the developer is actually working in.
# If secure-commit is cloned as a subfolder (e.g. my-app/secure-commit/),
# TARGET_GIT_ROOT resolves to my-app/ — the correct place for .git/hooks/.
# If secure-commit IS the top-level project, this equals PROJECT_ROOT.
TARGET_GIT_ROOT = None   # set by find_target_git_root() at runtime
GIT_HOOKS_DIR   = None   # set after TARGET_GIT_ROOT is known
HOOK_DEST       = None   # set after GIT_HOOKS_DIR is known

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


def find_target_git_root():
    """
    Find the real Git repo root to install the hook into.

    THE PROBLEM THIS SOLVES:
      If Secure-Commit is itself a cloned Git repo (has its own .git/),
      running 'git rev-parse --show-toplevel' from inside it will stop at
      Secure-Commit's own .git/ and never find the parent project's .git/.

      Example (WRONG without this fix):
        simple-java-docker/          ← real project (.git/ here)
        └── Secure-Commit/           ← also a git repo (.git/ here)
            └── install.py

      git rev-parse from Secure-Commit/ → returns Secure-Commit/ (WRONG)
      git rev-parse from simple-java-docker/ → returns simple-java-docker/ (CORRECT)

    THE FIX:
      First try git rev-parse from the PARENT directory of install.py.
      If the parent is a Git repo, that is our target.
      Only if the parent is NOT a Git repo do we fall back to PROJECT_ROOT.
    """
    global TARGET_GIT_ROOT, GIT_HOOKS_DIR, HOOK_DEST

    # ── Step 1: Try the parent folder first ───────────────────────────────────
    # This handles the case where Secure-Commit is a cloned subfolder with its
    # own .git/ inside a larger project that also has a .git/.
    parent_dir = PROJECT_ROOT.parent
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        cwd=str(parent_dir),
    )

    if result.returncode == 0:
        candidate = Path(result.stdout.strip())
        # Only use the parent's git root if it is actually OUTSIDE our folder.
        # This avoids an edge case where parent_dir itself is not in any repo.
        if candidate != PROJECT_ROOT:
            TARGET_GIT_ROOT = candidate
            info(f"Detected subfolder install. Target project: {TARGET_GIT_ROOT}")
            _set_hook_paths()
            ok(f"Target Git root confirmed: {TARGET_GIT_ROOT}")
            return

    # ── Step 2: Fall back — Secure-Commit IS the top-level project ────────────
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )

    if result.returncode != 0:
        err("Not inside a Git repository. Run this installer from inside a Git\n"
            "  repository, or from a folder inside a project that has a .git/ folder.")
        sys.exit(1)

    TARGET_GIT_ROOT = Path(result.stdout.strip())
    _set_hook_paths()
    ok(f"Target Git root confirmed: {TARGET_GIT_ROOT}")


def _set_hook_paths():
    """Set GIT_HOOKS_DIR and HOOK_DEST once TARGET_GIT_ROOT is known."""
    global GIT_HOOKS_DIR, HOOK_DEST
    GIT_HOOKS_DIR = TARGET_GIT_ROOT / ".git" / "hooks"
    HOOK_DEST     = GIT_HOOKS_DIR / "pre-commit"   # No .py — Git requirement



def check_git_hooks_dir():
    """Create .git/hooks/ in the TARGET project if it doesn't exist."""
    GIT_HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    ok(f"Git hooks directory confirmed: {GIT_HOOKS_DIR}")


def create_virtual_environment():
    """Create .venv if it doesn't already exist."""
    if VENV_DIR.exists() and VENV_PIP.exists():
        ok(f"Virtual environment already exists: {VENV_DIR}")
        return
    elif VENV_DIR.exists():
        warn("Found incomplete virtual environment. Cleaning up...")
        shutil.rmtree(VENV_DIR)

    info("Creating virtual environment (.venv)...")
    result = subprocess.run(
        [sys.executable, "-m", "venv", str(VENV_DIR)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error_msg = result.stderr.strip() or result.stdout.strip()
        err(f"Failed to create virtual environment:\n{error_msg}")
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
    hook_content = f"""#!/usr/bin/env python3
# Secure-Commit Pre-Commit Hook
# Auto-generated by install.py — do not edit manually.
# To reinstall: python install.py
import sys
import os
import subprocess
from pathlib import Path

# ── Absolute paths baked in at install time ────────────────────────────────────
venv_python = Path(r"{VENV_PYTHON}")
hook_script  = Path(r"{HOOK_SOURCE}")

# git_root = the REAL project we are protecting (may differ from Secure-Commit's
# own folder when Secure-Commit is installed as a subfolder inside a larger repo).
git_root     = Path(r"{TARGET_GIT_ROOT}")

if not venv_python.exists():
    print("  [SECURE-COMMIT] .venv not found. Run: python install.py")
    sys.exit(1)

# Pass git_root to pre_commit.py via an environment variable so it knows
# which repo to scan — this is critical for subfolder installs.
env = os.environ.copy()
env["SECURE_COMMIT_GIT_ROOT"] = str(git_root)

result = subprocess.run(
    [str(venv_python), str(hook_script)],
    cwd=str(git_root),   # run from the REAL project root, not Secure-Commit's folder
    env=env,
)
sys.exit(result.returncode)
"""

    HOOK_DEST.write_text(hook_content, encoding="utf-8")

    # On Linux/macOS: set executable bit (not needed on Windows)
    if not IS_WINDOWS:
        HOOK_DEST.chmod(0o755)
        ok("Hook file made executable (chmod +x)")
    else:
        # On Windows, Git does not process the #!/usr/bin/env shebang.
        # We write a companion .cmd file that Git Bash picks up automatically.
        # Git checks for pre-commit.cmd before pre-commit on Windows.
        cmd_dest = GIT_HOOKS_DIR / "pre-commit.cmd"
        # Use forward slashes inside the .cmd for Git Bash compatibility
        venv_py_cmd  = str(VENV_PYTHON).replace("/", "\\")
        hook_src_cmd = str(HOOK_SOURCE).replace("/", "\\")
        git_root_cmd = str(TARGET_GIT_ROOT).replace("/", "\\")
        cmd_content = (
            f"@echo off\r\n"
            f"set SECURE_COMMIT_GIT_ROOT={git_root_cmd}\r\n"
            f"cd /d \"{git_root_cmd}\"\r\n"
            f"\"{venv_py_cmd}\" \"{hook_src_cmd}\" %*\r\n"
        )
        cmd_dest.write_text(cmd_content, encoding="utf-8")
        ok(f"Windows .cmd shim installed: {cmd_dest}")

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
    """Remove the pre-commit hook from .git/hooks/ of the TARGET project."""
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
        find_target_git_root()     # need TARGET_GIT_ROOT to know where HOOK_DEST is
        uninstall()
        return

    info("Starting installation...")
    print()

    check_python_version()
    find_target_git_root()     # ← discovers TARGET_GIT_ROOT, GIT_HOOKS_DIR, HOOK_DEST
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
