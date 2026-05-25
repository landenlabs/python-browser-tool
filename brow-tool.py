#!/usr/bin/env python3
"""brow-tool - Browser directory analysis and forensics tool"""

import argparse
import json
import os
import platform
import sys
import traceback
from pathlib import Path

VERSION = "v0.06.00 (May-2026)"


# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

_RED    = '\033[31m'
_RESET  = '\033[0m'
_USE_COLOR = False


def _init_colors():
    """Enable ANSI color output if the terminal supports it."""
    global _USE_COLOR
    if os.environ.get('NO_COLOR'):
        return
    if not sys.stdout.isatty():
        return
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong(0)
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            return
    _USE_COLOR = True


def _c(text, color):
    """Wrap text in an ANSI color if colors are enabled."""
    return f"{color}{text}{_RESET}" if _USE_COLOR else text


# ---------------------------------------------------------------------------
# Default browser locations per OS
# ---------------------------------------------------------------------------

def get_default_chrome_paths():
    """Return existing default Chrome User Data locations for the current OS."""
    system = platform.system()
    candidates = []

    if system == 'Windows':
        local = os.environ.get('LOCALAPPDATA')
        if local:
            base = Path(local)
            candidates += [
                base / 'Google' / 'Chrome'      / 'User Data',
                base / 'Google' / 'Chrome Beta' / 'User Data',
                base / 'Google' / 'Chrome SxS'  / 'User Data',   # Canary
                base / 'Chromium'               / 'User Data',
            ]
    elif system == 'Darwin':
        home = Path.home()
        support = home / 'Library' / 'Application Support'
        candidates += [
            support / 'Google' / 'Chrome',
            support / 'Google' / 'Chrome Beta',
            support / 'Google' / 'Chrome Canary',
            support / 'Chromium',
        ]
    else:  # Linux / *BSD
        home = Path.home()
        cfg  = home / '.config'
        candidates += [
            cfg / 'google-chrome',
            cfg / 'google-chrome-beta',
            cfg / 'google-chrome-unstable',
            cfg / 'chromium',
        ]

    return [p for p in candidates if p.exists()]


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def _resolve_message(ext_root, value, default_locale):
    """
    Resolve a Chrome '__MSG_key__' string by reading the extension's
    _locales/<locale>/messages.json. Returns the resolved string, or the
    original value if it isn't a message reference or can't be resolved.

    Chrome's lookup order: current UI locale → language family → default_locale.
    Without access to the running browser's UI locale we try, in order:
    default_locale, its language family, and a handful of common fallbacks.
    """
    if not isinstance(value, str):
        return value
    if not (value.startswith('__MSG_') and value.endswith('__')):
        return value

    key = value[6:-2]  # strip '__MSG_' and '__'
    if not key:
        return value

    locales_dir = ext_root / '_locales'
    if not _safe_exists(locales_dir):
        return value

    candidates = []
    if default_locale:
        candidates.append(default_locale)
        candidates.append(default_locale.replace('-', '_'))
        family = default_locale.split('-')[0].split('_')[0]
        if family and family not in candidates:
            candidates.append(family)
    # Common fallbacks for extensions that misdeclare or omit default_locale
    for loc in ('en', 'en_US', 'en_GB'):
        if loc not in candidates:
            candidates.append(loc)

    for loc in candidates:
        messages = locales_dir / loc / 'messages.json'
        if not _safe_exists(messages):
            continue
        try:
            with open(messages, 'r', encoding='utf-8-sig', errors='ignore') as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        # Chrome message-key lookup is case-insensitive
        target = key.lower()
        for k, entry in data.items():
            if k.lower() == target and isinstance(entry, dict):
                msg = entry.get('message')
                if msg:
                    return msg
    return value  # leave the __MSG_...__ form so the caller can flag it


def get_extension_details(manifest_path):
    """Parse manifest.json and return (name, version, description, manifest_version)."""
    try:
        with open(manifest_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            data = json.load(f)

        name = data.get('name', 'Unknown')
        version = data.get('version', 'Unknown')
        description = data.get('description', 'No description provided.')
        manifest_version = data.get('manifest_version')  # int (typically 2 or 3); may be missing
        default_locale = data.get('default_locale')

        ext_root = Path(manifest_path).parent
        resolved_name = _resolve_message(ext_root, name, default_locale)
        resolved_desc = _resolve_message(ext_root, description, default_locale)

        # If resolution failed, mark the raw key so it's still readable
        if resolved_name is name and isinstance(name, str) \
                and name.startswith('__MSG_') and name.endswith('__'):
            resolved_name = f"{name} (unresolved)"
        if resolved_desc is description and isinstance(description, str) \
                and description.startswith('__MSG_') and description.endswith('__'):
            resolved_desc = f"{description} (unresolved)"

        return resolved_name, version, resolved_desc, manifest_version
    except Exception:
        return "Unreadable Manifest", "Unknown", "Could not parse JSON.", None


def read_manifest_version(manifest_path):
    """Return just the manifest_version field from a manifest.json, or None."""
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        return data.get('manifest_version')
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Chrome scanning
# ---------------------------------------------------------------------------

def _safe_iterdir(path):
    """Iterate a directory, returning [] on permission / OS errors."""
    try:
        return list(path.iterdir())
    except (PermissionError, OSError) as err:
        print(f"  [!] Skipping (cannot list): {path}  ({err.strerror or err})", file=sys.stderr)
        return []


def _safe_exists(path):
    """Test path existence, treating permission errors as 'inaccessible' rather than crashing."""
    try:
        return path.exists()
    except (PermissionError, OSError):
        return False


def get_chrome_version(root_path):
    """
    Return the Chrome version string recorded in this User Data directory, or None.

    Reads '<User Data>/Last Version' — a single-line text file Chrome writes after
    a successful launch (e.g. '131.0.6778.85'). This reflects the version that
    last ran with this profile set, which is what these extensions were validated
    against.
    """
    last_version = root_path / 'Last Version'
    if not _safe_exists(last_version):
        return None
    try:
        with open(last_version, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().strip() or None
    except OSError:
        return None


def get_min_manifest_version(chrome_version):
    """
    Given a Chrome version string, return the minimum extension manifest_version
    that Chrome will load, plus a short note string.

    Returns (min_mv, note) or (None, None) if the version can't be parsed.

    Timeline:
      Chrome 127 (Jun 2024): Manifest V2 disabled by default for users
      Chrome 138 (Jun 2025): Manifest V2 fully removed
    """
    if not chrome_version:
        return None, None
    try:
        major = int(chrome_version.split('.')[0])
    except (ValueError, IndexError):
        return None, None
    if major >= 138:
        return 3, "Manifest V2 removed"
    if major >= 127:
        return 3, "Manifest V2 disabled by default"
    return 2, "Manifest V2 and V3 supported"


def print_chrome_header(root_path):
    """Print the Chrome version + minimum supported manifest_version line."""
    version = get_chrome_version(root_path)
    if version is None:
        print(f"[*] Chrome version: (unknown — no 'Last Version' file in {root_path})")
        return
    min_mv, note = get_min_manifest_version(version)
    if min_mv is None:
        print(f"[*] Chrome version: {version}  (minimum extension manifest_version: unknown)")
    else:
        print(f"[*] Chrome version: {version}  "
              f"(minimum extension manifest_version: {min_mv} — {note})")


def load_chrome_profile_names(root_path):
    """
    Return a {profile_dir_name: display_name} mapping for a Chrome User Data root.

    Tries 'Local State' first (one read covers all profiles); falls back to each
    profile's own 'Preferences' file. Returns {} on any failure.
    """
    mapping = {}

    local_state = root_path / 'Local State'
    if _safe_exists(local_state):
        try:
            with open(local_state, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            info_cache = data.get('profile', {}).get('info_cache', {}) or {}
            for dir_name, info in info_cache.items():
                display = info.get('name') or info.get('shortcut_name') or info.get('gaia_name')
                if display:
                    mapping[dir_name] = display
        except (OSError, ValueError):
            pass

    # Fallback: per-profile Preferences for anything still missing
    for profile_item in _safe_iterdir(root_path):
        if profile_item.name in mapping:
            continue
        try:
            if not profile_item.is_dir():
                continue
        except (PermissionError, OSError):
            continue
        if not (profile_item.name == 'Default' or profile_item.name.startswith('Profile')):
            continue
        prefs = profile_item / 'Preferences'
        if not _safe_exists(prefs):
            continue
        try:
            with open(prefs, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            display = data.get('profile', {}).get('name')
            if display:
                mapping[profile_item.name] = display
        except (OSError, ValueError):
            continue

    return mapping


def scan_chrome_directory(chrome_dir):
    """Scan a Chrome user-data folder for profiles and their extensions."""
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return 0

    print_chrome_header(root_path)
    print(f"[*] Scanning for extensions in: {root_path}\n")

    profile_names = load_chrome_profile_names(root_path)
    chrome_version = get_chrome_version(root_path)
    min_mv, _ = get_min_manifest_version(chrome_version)

    extensions_found = 0
    skipped = 0

    for profile_item in sorted(_safe_iterdir(root_path), key=lambda p: p.name.lower()):
        # Standard profiles are named 'Default' or 'Profile X'
        try:
            if not (profile_item.is_dir() and
                    (profile_item.name == 'Default' or profile_item.name.startswith('Profile'))):
                continue
        except (PermissionError, OSError):
            continue

        extensions_dir = profile_item / "Extensions"
        if not (_safe_exists(extensions_dir) and extensions_dir.is_dir()):
            continue

        display = profile_names.get(profile_item.name)
        header_label = f'{profile_item.name}  ("{display}")' if display else profile_item.name
        profile_field = f'{profile_item.name}  ("{display}")' if display else profile_item.name
        print(f"=== Profile: {header_label} ===")
        profile_has_extensions = False

        for ext_id_dir in _safe_iterdir(extensions_dir):
            try:
                if not ext_id_dir.is_dir():
                    continue
            except (PermissionError, OSError):
                skipped += 1
                continue

            # Extensions have version subfolders which house the manifest.json
            for version_dir in _safe_iterdir(ext_id_dir):
                manifest_file = version_dir / "manifest.json"
                if not _safe_exists(manifest_file):
                    # May be a permission denial on a component extension; count and move on
                    try:
                        if not version_dir.is_dir():
                            continue
                    except (PermissionError, OSError):
                        pass
                    continue

                profile_has_extensions = True
                extensions_found += 1

                name, version, desc, mv = get_extension_details(manifest_file)

                if mv is None:
                    mv_display = "(none)"
                elif min_mv is not None and mv < min_mv:
                    mv_display = _c(f"{mv}  (UNSUPPORTED — below browser minimum {min_mv})", _RED)
                else:
                    mv_display = str(mv)

                print(f"  Name             : {name}")
                print(f"  Version          : {version}")
                print(f"  Manifest Version : {mv_display}")
                print(f"  Description      : {desc}")
                print(f"  Profile          : {profile_field} (Enabled/Installed)")
                print(f"  Path             : {manifest_file}")
                print("-" * 50)

        if not profile_has_extensions:
            print("  (No user extensions found in this profile)")
            print("-" * 50)
        print()

    if extensions_found == 0:
        print("[-] No active profile extensions detected. (Component updates ignored)\n")

    if skipped:
        print(f"[!] {skipped} extension entr{'y' if skipped == 1 else 'ies'} "
              f"could not be accessed (permission denied).\n", file=sys.stderr)

    return extensions_found


def scan_chrome(chrome_arg):
    """Dispatch a Chrome scan: explicit path, or all default OS locations."""
    if chrome_arg and chrome_arg != 'AUTO':
        return scan_chrome_directory(chrome_arg)

    paths = get_default_chrome_paths()
    if not paths:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return 0

    print(f"[*] No --chrome path given; scanning {len(paths)} default location(s) "
          f"for {platform.system()}.\n")
    total = 0
    for p in paths:
        total += scan_chrome_directory(str(p))
    return total


# ---------------------------------------------------------------------------
# Per-profile extension counts
# ---------------------------------------------------------------------------

def count_profile_extensions(profile_dir, min_mv=None):
    """
    Return (installed, enabled, unsupported) for a profile dir.

    'installed'   = extension IDs under Extensions/ that have at least one
                    version subfolder containing manifest.json.
    'enabled'     = installed IDs whose Preferences 'extensions.settings.<id>.state'
                    is 1. If state is missing the extension is treated as enabled.
    'unsupported' = installed IDs whose manifest_version is below min_mv (the
                    minimum the running Chrome will load). 0 if min_mv is None.
    """
    extensions_dir = profile_dir / "Extensions"
    # Map ext_id -> manifest_version (int or None) for the chosen version dir
    installed = {}
    if _safe_exists(extensions_dir) and extensions_dir.is_dir():
        for ext_id_dir in _safe_iterdir(extensions_dir):
            try:
                if not ext_id_dir.is_dir():
                    continue
            except (PermissionError, OSError):
                continue
            # Prefer the highest-named version dir (Chrome's selection rule)
            version_dirs = sorted(
                (d for d in _safe_iterdir(ext_id_dir) if _safe_exists(d / "manifest.json")),
                key=lambda d: d.name,
                reverse=True,
            )
            if not version_dirs:
                continue
            mv = read_manifest_version(version_dirs[0] / "manifest.json")
            installed[ext_id_dir.name] = mv

    settings = {}
    prefs = profile_dir / "Preferences"
    if _safe_exists(prefs):
        try:
            with open(prefs, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            settings = data.get('extensions', {}).get('settings', {}) or {}
        except (OSError, ValueError):
            settings = {}

    enabled = 0
    for ext_id in installed:
        info = settings.get(ext_id) or {}
        # state: 0=disabled, 1=enabled, missing → treat as enabled
        if info.get('state', 1) == 1:
            enabled += 1

    unsupported = 0
    if min_mv is not None:
        for mv in installed.values():
            if mv is not None and mv < min_mv:
                unsupported += 1

    return len(installed), enabled, unsupported


def list_chrome_profiles_directory(chrome_dir):
    """List profiles in a Chrome user-data folder with extension counts."""
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return 0

    print_chrome_header(root_path)
    print(f"[*] Profiles in: {root_path}\n")

    profile_names  = load_chrome_profile_names(root_path)
    chrome_version = get_chrome_version(root_path)
    min_mv, _      = get_min_manifest_version(chrome_version)

    rows = []
    for profile_item in sorted(_safe_iterdir(root_path), key=lambda p: p.name.lower()):
        try:
            if not profile_item.is_dir():
                continue
        except (PermissionError, OSError):
            continue
        if not (profile_item.name == 'Default' or profile_item.name.startswith('Profile')):
            continue

        display = profile_names.get(profile_item.name, '')
        installed, enabled, unsupported = count_profile_extensions(profile_item, min_mv)
        rows.append((profile_item.name, display, installed, enabled, unsupported))

    if not rows:
        print("  (no profiles found)\n")
        return 0

    name_w    = max(len("Profile"),      max(len(r[0]) for r in rows))
    display_w = max(len("Display Name"), max(len(r[1]) for r in rows))
    unsup_label = "Unsupported" if min_mv is not None else "Unsupported*"

    header = (f"  {'Profile'.ljust(name_w)}   "
              f"{'Display Name'.ljust(display_w)}   "
              f"Installed   Enabled   {unsup_label}")
    sep = (f"  {'-' * name_w}   {'-' * display_w}   "
           f"---------   -------   {'-' * len(unsup_label)}")
    print(header)
    print(sep)
    for name, display, installed, enabled, unsupported in rows:
        unsup_cell = f"{unsupported:>{len(unsup_label)}}"
        if min_mv is not None and unsupported > 0:
            unsup_cell = _c(unsup_cell, _RED)
        print(f"  {name.ljust(name_w)}   "
              f"{display.ljust(display_w)}   "
              f"{installed:>9}   {enabled:>7}   {unsup_cell}")
    if min_mv is None:
        print("\n  * Cannot evaluate: Chrome version unknown, so no minimum manifest_version baseline.")
    print()
    return len(rows)


def list_chrome_profiles(chrome_arg):
    """Dispatch a Chrome profile listing: explicit path, or default OS locations."""
    if chrome_arg and chrome_arg != 'AUTO':
        return list_chrome_profiles_directory(chrome_arg)

    paths = get_default_chrome_paths()
    if not paths:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return 0

    print(f"[*] No --chrome path given; listing profiles from {len(paths)} "
          f"default location(s) for {platform.system()}.\n")
    total = 0
    for p in paths:
        total += list_chrome_profiles_directory(str(p))
    return total


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"brow-tool {VERSION}\nBrowser directory analysis and forensics tool.",
        epilog="""Examples:
  # Scan Chrome at the default OS-specific User Data location(s):
  brow-tool.py --summary --chrome

  # List profiles with installed/enabled extension counts:
  brow-tool.py --profiles --chrome

  # Both at once:
  brow-tool.py --summary --profiles --chrome

  # Scan a specific Chrome User Data directory:
  brow-tool.py --summary --chrome "%LOCALAPPDATA%\\Google\\Chrome\\User Data"
  brow-tool.py --summary --chrome ~/.config/google-chrome
  brow-tool.py --summary --chrome "~/Library/Application Support/Google/Chrome"

Default locations searched when --chrome is given without a path:
  Windows:  %LOCALAPPDATA%\\Google\\Chrome\\User Data
            %LOCALAPPDATA%\\Google\\Chrome Beta\\User Data
            %LOCALAPPDATA%\\Google\\Chrome SxS\\User Data   (Canary)
            %LOCALAPPDATA%\\Chromium\\User Data
  macOS:    ~/Library/Application Support/Google/Chrome
            ~/Library/Application Support/Google/Chrome Beta
            ~/Library/Application Support/Google/Chrome Canary
            ~/Library/Application Support/Chromium
  Linux:    ~/.config/google-chrome
            ~/.config/google-chrome-beta
            ~/.config/google-chrome-unstable
            ~/.config/chromium

Notes:
  The --chrome path should point to the Chrome "User Data" directory, which
  contains profile subdirectories such as 'Default' and 'Profile 1'.
  Future versions may add --firefox and --opera switches with the same behavior.
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Provide a summary of profiles and their installed extensions',
    )
    parser.add_argument(
        '--profiles',
        action='store_true',
        help='List profile dir, browser display name, and installed/enabled extension counts',
    )
    parser.add_argument(
        '--chrome',
        nargs='?',
        const='AUTO',
        default=None,
        metavar='PATH',
        help='Scan Chrome. With no value, uses the OS default User Data location(s); '
             'with a value, scans the given path.',
    )
    parser.add_argument(
        '--no-color', action='store_true',
        help='Disable colored output (also honors the NO_COLOR env var)',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    if not args.no_color:
        _init_colors()

    if args.chrome is None:
        parser.error("at least one browser must be specified (e.g., --chrome)")

    if not (args.summary or args.profiles):
        parser.error("specify at least one of --summary or --profiles")

    if args.profiles:
        list_chrome_profiles(args.chrome)

    if args.summary:
        scan_chrome(args.chrome)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
