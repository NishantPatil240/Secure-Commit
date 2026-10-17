#!/usr/bin/env python3
"""
cli.py — Secure-Commit Command Line Interface
===============================================
Entry point for the Secure-Commit scanner.

Usage:
    secure-commit scan [path] [--format ansi|json|sarif]
    secure-commit install
    secure-commit uninstall
    secure-commit history [--depth N]
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.policy_engine import load_policies
from engine.directory_scanner import scan_directory
from engine import reporter
import install

try:
    import git
    from engine.secret_scanner import scan_commit_history
except ImportError:
    git = None

def run_scan(args):
    """Run full-project scan."""
    try:
        policies = load_policies()
    except Exception as exc:
        print(f"Failed to load policy.yaml: {exc}")
        return 1

    path_to_scan = Path(args.path).resolve()
    if not path_to_scan.exists():
        print(f"Error: Path '{path_to_scan}' does not exist.")
        return 1
        
    if args.format == "ansi":
        reporter.print_banner()
        print(f"  Scanning directory: {path_to_scan}\n")

    findings = scan_directory(path_to_scan, policies)
    
    if args.format == "json":
        print(reporter.format_json(findings))
        return 1 if any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings) else 0
    elif args.format == "sarif":
        print(reporter.format_sarif(findings))
        return 1 if any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings) else 0
    else:
        for finding in findings:
            reporter.print_finding(finding)

        blocking = [f for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
        warnings = [f for f in findings if f.get("severity", "").upper() in ("MEDIUM", "LOW")]

        reporter.print_summary(blocking, warnings)
        return 1 if blocking else 0

def run_history(args):
    """Run history scan."""
    if not git:
        print("GitPython not installed. Run 'python install.py' first.")
        return 1
        
    try:
        policies = load_policies()
    except Exception as exc:
        print(f"Failed to load policy.yaml: {exc}")
        return 1
        
    try:
        repo = git.Repo(PROJECT_ROOT, search_parent_directories=True)
    except Exception as exc:
        print(f"Could not open Git repository: {exc}")
        return 1
        
    secret_patterns = policies.get("secret_patterns", [])
    
    if args.format == "ansi":
        reporter.print_banner()
        reporter.print_history_scan_header(args.depth)
        
    findings = scan_commit_history(repo, secret_patterns, depth=args.depth)
    
    if args.format == "json":
        print(reporter.format_json(findings))
    elif args.format == "sarif":
        print(reporter.format_sarif(findings))
    else:
        for finding in findings:
            reporter.print_finding(finding)
            
        blocking = [f for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
        warnings = [f for f in findings if f.get("severity", "").upper() in ("MEDIUM", "LOW")]
        reporter.print_summary(blocking, warnings)
        
    return 1 if any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings) else 0

def main():
    parser = argparse.ArgumentParser(description="Secure-Commit Governance Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    parser_scan = subparsers.add_parser("scan", help="Scan a directory for secrets and IaC violations")
    parser_scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")
    parser_scan.add_argument("--format", choices=["ansi", "json", "sarif"], default="ansi", help="Output format")

    # history
    parser_hist = subparsers.add_parser("history", help="Scan Git history for ghost secrets")
    parser_hist.add_argument("--depth", type=int, default=50, help="Number of commits to scan")
    parser_hist.add_argument("--format", choices=["ansi", "json", "sarif"], default="ansi", help="Output format")

    # install
    parser_inst = subparsers.add_parser("install", help="Install the pre-commit hook")
    
    # uninstall
    parser_uninst = subparsers.add_parser("uninstall", help="Uninstall the pre-commit hook")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "history":
        sys.exit(run_history(args))
    elif args.command == "install":
        install.run_install()
        sys.exit(0)
    elif args.command == "uninstall":
        install.run_uninstall()
        sys.exit(0)

if __name__ == "__main__":
    main()
