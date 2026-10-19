# File Integrity Monitor

A small Python tool that detects when files in a folder are **added, removed or modified**, for example a defaced web page, a dropped web shell or an edited config file.

It records a SHA-256 hash of every file (the *baseline*) and later compares the folder against it. No dependencies outside the standard library.

## Usage

```bash
# 1. Record the trusted state
python -m fim init /var/www/site

# 2. Later, check for changes (exit code 0 = clean, 1 = changes, 2 = error)
python -m fim check /var/www/site
MODIFIED  index.html
ADDED     uploads/shell.php
REMOVED   conf/app.ini

1 modified, 1 added, 1 removed

# Machine readable output for scripts or cron
python -m fim check /var/www/site --json

# 3. Accept legitimate changes as the new baseline
python -m fim update /var/www/site
```

Options: `-b/--baseline FILE` stores the baseline elsewhere, `-x/--exclude GLOB` skips paths (repeatable), `init --force` overwrites a baseline.

## Protecting the baseline

An attacker who can change your files can often change the baseline too. Set `FIM_KEY` and the baseline is signed with **HMAC-SHA256**:

```bash
export FIM_KEY='a long random secret'
python -m fim init /var/www/site
```

`check` and `update` then refuse to run if the baseline was edited, the signature is missing or the key is wrong. Keep the key outside the monitored machine (for example in the environment of a cron job run by another user), and ideally store the baseline with `-b` on read-only or separate storage.

## Design notes

- Files are hashed in 64 KB chunks, so large files do not load into memory.
- Symlinks are not followed, so a link cannot redirect the scan outside the folder.
- `.git` and `__pycache__` are skipped, and the baseline file never reports itself as a change.
- Baselines are written atomically (temp file + rename) so a crash cannot leave a half-written baseline.
- Signatures are compared with `hmac.compare_digest` (constant time).
- `update` verifies the old baseline before replacing it, so tampering cannot be laundered into a new baseline.

## Tests

```bash
pip install pytest
python -m pytest
```

## Project structure

```
fim/
  core.py     scanning, hashing, baseline signing and comparison
  cli.py      init / check / update commands
tests/
  test_fim.py
```
