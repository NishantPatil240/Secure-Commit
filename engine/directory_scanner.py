"""
directory_scanner.py — Full Project Scanner
=============================================
Recursively walks a directory tree to find all scannable files,
respecting .gitignore and skipping binary files.

Public interface:
    scan_directory(root_path: Path, policies: dict) -> list[dict]
"""
import os
import fnmatch
from pathlib import Path

from engine.iac_parser import parse_file
from engine.policy_engine import run_policy_engine
from engine.utils import should_skip_file
from engine.secret_scanner import scan_text

# Directories to always ignore
DEFAULT_IGNORE_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules", ".idea", ".vscode"
}

def load_gitignore(root_path):
    """Load .gitignore patterns if the file exists."""
    gitignore_path = root_path / ".gitignore"
    patterns = []
    if gitignore_path.exists():
        with open(gitignore_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.endswith("/"):
                        line = line[:-1]
                    if line.startswith("/"):
                        line = line[1:]
                    patterns.append(line)
    return patterns

def is_ignored(path, root_path, gitignore_patterns):
    """Check if a path matches any gitignore pattern or default ignores."""
    try:
        rel_path = path.relative_to(root_path)
    except ValueError:
        return True

    rel_str = str(rel_path).replace("\\", "/")
    
    for part in rel_path.parts:
        if part in DEFAULT_IGNORE_DIRS:
            return True
            
    for pattern in gitignore_patterns:
        if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(rel_path.name, pattern):
            return True
        # also check if the pattern matches a directory somewhere in the path
        # e.g. pattern "build" matches "build/foo.txt"
        for i in range(1, len(rel_path.parts)):
            prefix_str = "/".join(rel_path.parts[:i])
            if fnmatch.fnmatch(prefix_str, pattern):
                return True
            
    return False

def scan_directory(root_path, policies):
    """
    Scan all files in root_path.
    """
    root_path = Path(root_path).resolve()
    all_findings = []
    
    secret_patterns = policies.get("secret_patterns", [])
    
    # Store gitignore patterns per directory to inherit them
    dir_patterns = {}
    
    for dirpath, dirnames, filenames in os.walk(root_path):
        current_dir = Path(dirpath)
        
        # Load .gitignore if present in current_dir
        local_patterns = load_gitignore(current_dir)
        
        # Inherit patterns from parent directory
        parent_patterns = []
        if current_dir != root_path and current_dir.parent in dir_patterns:
            parent_patterns = dir_patterns[current_dir.parent]
            
        combined_patterns = parent_patterns + local_patterns
        dir_patterns[current_dir] = combined_patterns
        
        # Modify dirnames in-place to prune ignored directories
        dirnames[:] = [d for d in dirnames if not is_ignored(current_dir / d, root_path, combined_patterns)]
        
        for filename in filenames:
            file_path = current_dir / filename
            if is_ignored(file_path, root_path, combined_patterns):
                continue
                
            if should_skip_file(file_path):
                continue
                
            rel_path_str = str(file_path.relative_to(root_path)).replace("\\", "/")
            
            # 1. IaC Policy Scan
            parsed = parse_file(file_path)
            if parsed is not None:
                # Update file_path to be relative for nice reporting
                parsed["file_path"] = rel_path_str
                iac_findings = run_policy_engine(parsed, policies)
                all_findings.extend(iac_findings)
                
            # 2. Secret Scan
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                secret_findings = scan_text(content, rel_path_str, secret_patterns)
                all_findings.extend(secret_findings)
            except Exception:
                pass
                
    return all_findings
