# Secure-Commit Framework - Project Context

**Purpose of this file**: This file is intended to serve as "AI Memory" or a human-readable summary if this project folder is moved to a new environment, a new user account, or a new computer. 

## Project Overview
**Secure-Commit** is a local, offline, Git pre-commit hook framework. It is designed to act as a security guard that physically blocks a developer from committing code if it contains:
1. Hardcoded Secrets (AWS keys, passwords).
2. Insecure Infrastructure-as-Code (IaC) configurations (e.g., Docker containers running as root).
3. Secrets lurking in Git history.

*Detailed architecture and design rules can be found in `docs/00_project_overview.md`.*

## Current Status
**Status: ✅ Core Implementation & End-to-End Testing Complete**

The project has successfully gone through its main implementation phases and is fully functional. 

### What has been built:
1. **The Policy Engine (`engine/policy_engine.py`, `config/policy.yaml`)**: Rules are driven by a central YAML configuration.
2. **Scanners (`engine/secret_scanner.py`, `engine/iac_parser.py`)**: 
   - Uses regex to find secrets.
   - Parses Dockerfiles and Terraform configurations to validate against YAML policies.
3. **Pre-commit Hook (`hooks/pre_commit.py`)**: The main script that runs during `git commit`, evaluates changes, and exits with code `1` (block) or `0` (allow).
4. **Setup System (`install.py`)**: A robust installer that sets up a local virtual environment (`.venv`), installs dependencies, and automatically wires the Python script to the `.git/hooks/pre-commit` file.
5. **Testing Framework (`tests/`)**: Includes fixtures of "good" and "bad" IaC files to ensure the engine correctly flags violations and passes safe code.

### Recent Milestones:
- **Phase 1 (Building)**: Created the core engines, parsers, and scanners.
- **Phase 2 (Finalizing)**: Completed the final validation phase. The `install.py` script was run to wire the hook into the repository. We performed end-to-end testing by committing bad infrastructure-as-code files (which were successfully blocked) and good files (which were allowed).

## How to Resume Work or Run on a New Machine
If you have just cloned or moved this repository to a new machine/account:

1. **Do not run `pip install` manually.**
2. Run the installer script from the root of the project:
   ```bash
   python install.py
   ```
   *This will automatically recreate the isolated `.venv`, install `PyYAML` and `GitPython`, and re-link the Git hook in the new environment.*
3. Test it by trying to commit a "bad" file (e.g., adding a dummy AWS key or using `USER root` in a Dockerfile). The hook should intercept and block the commit.

## Where to go next (Future Enhancements)
If you want to extend this project, some logical next steps would be:
- Adding more rules to `config/policy.yaml` (e.g., Kubernetes manifests, GitHub Actions workflow checks).
- Enhancing the forensic history scan to search deeper into past commits using GitPython.
- Adding auto-remediation (e.g., automatically fixing trailing whitespaces or simple formatting issues before commit).
