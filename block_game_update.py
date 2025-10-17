#!/usr/bin/env python3
import argparse
import os
import stat
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

########################################################################
# Minimal Valve KeyValue / ACF parser & writer (handles typical cases) #
########################################################################

class VDFParseError(Exception):
    pass

_token_re = re.compile(r'''
    \s*(
        "([^"\\]|\\.)*"        # quoted string
      | \{                     # open brace
      | \}                     # close brace
    )
''', re.VERBOSE)

def _unescape(s: str) -> str:
    return bytes(s, "utf-8").decode("unicode_escape")

def _tok(s: str):
    pos = 0
    n = len(s)
    while True:
        m = _token_re.match(s, pos)
        if not m:
            if pos < n and s[pos:].strip():
                raise VDFParseError(f"Unexpected input near: {s[pos:pos+80]!r}")
            break
        tok = m.group(1)
        pos = m.end()
        if tok.startswith('"'):
            yield _unescape(tok[1:-1])
        else:
            yield tok

def _parse_obj(tokens):
    obj = {}
    key = None
    for t in tokens:
        if t == "}":
            return obj
        if t == "{":
            raise VDFParseError("Unexpected '{' while expecting key")
        # t is a key (string)
        key = t
        try:
            nxt = next(tokens)
        except StopIteration:
            raise VDFParseError("Unexpected EOF after key")
        if nxt == "{":
            obj[key] = _parse_obj(tokens)
        else:
            # nxt is a value string
            obj[key] = nxt
    raise VDFParseError("Unexpected EOF (missing '}')")

def parse_vdf(text: str):
    tokens = iter(_tok(text))
    # Accept either {root} or key { ... } top-level
    # appmanifest_* uses "AppState" { ... }
    # app_info_print outputs starts with the appid key
    toks = list(tokens)
    # re-tokenize through an iterator again
    tokens = iter(toks)
    try:
        first = next(tokens)
    except StopIteration:
        return {}
    if first == "{":
        return _parse_obj(tokens)
    else:
        # first is a key, next should be "{"
        try:
            nxt = next(tokens)
        except StopIteration:
            raise VDFParseError("Unexpected EOF after top-level key")
        if nxt != "{":
            raise VDFParseError("Expected '{' after top-level key")
        return {first: _parse_obj(tokens)}

def _escape(s: str) -> str:
    # Steam is happy with basic escaping
    return s.replace("\\", "\\\\").replace('"', '\\"')

def dump_vdf(obj):
    def dump_obj(o, depth):
        lines = []
        for k, v in o.items():
            if isinstance(v, dict):
                lines.append(f'{"\t"*depth}"{_escape(str(k))}"')
                lines.append(f'{"\t"*depth}' + "{")
                lines.extend(dump_obj(v, depth + 1))
                lines.append(f'{"\t"*depth}' + "}")
            else:
                lines.append(f'{"\t"*depth}"{_escape(str(k))}"\t\t"{_escape(str(v))}"')
        return lines

    # If there’s exactly one top-level key whose value is a dict (e.g. "AppState"),
    # emit the classic Valve style:
    # "AppState"
    # {
    #     ...
    # }
    if isinstance(obj, dict) and len(obj) == 1:
        (k, v), = obj.items()
        if isinstance(v, dict):
            body = "\n".join(dump_obj(v, 1))
            return f'"{_escape(str(k))}"\n' + "{\n" + body + "\n}\n"

    # Otherwise, dump as a bare object (used for other VDF shapes)
    return "{\n" + "\n".join(dump_obj(obj, 1)) + "\n}\n"

#########################################
# SteamCMD querying and manifest update #
#########################################

def run_steamcmd(steamcmd, username, password, appid):
    login = ["+login", username] if username and username != "anonymous" else ["+login", "anonymous"]
    if username and username != "anonymous" and password:
        login = ["+login", username, password]
    cmd = [steamcmd, *login, "+app_info_update", "1", "+app_info_print", str(appid), "+quit"]
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return out
    except subprocess.CalledProcessError as e:
        print("steamcmd failed. Output:\n", e.output, file=sys.stderr)
        raise

def extract_appinfo_dict(steam_out: str, appid: str):
    """
    Robustly slice out the single VDF block that starts with "<appid>" and the
    following balanced-brace object, ignoring any trailing SteamCMD logs.
    """
    key = f'"{appid}"'
    start = steam_out.find(key)
    if start == -1:
        # Sometimes SteamCMD says "No app info for AppID ..." for private/protected apps
        # or before app_info_update finishes. Surface a clear error.
        raise VDFParseError(f"Could not locate VDF block for app {appid} in steamcmd output.")

    # Find the first '{' after "<appid>"
    i = steam_out.find("{", start)
    if i == -1:
        raise VDFParseError("Malformed app info (no '{' after appid).")

    # Walk forward to find the matching closing '}' for this object
    depth = 0
    end = None
    for pos in range(i, len(steam_out)):
        ch = steam_out[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break

    if end is None:
        raise VDFParseError("Malformed app info (unbalanced braces).")

    vdf_text = steam_out[start:end]  # "<appid>" { ...balanced... }
    # Now parse only this clean slice
    return parse_vdf(vdf_text)
    
def _get_buildid(ai: dict, branch: str, current_buildid: str | None):
    """
    Find buildid for a branch. Steam sometimes puts it at:
      1) ai["branches"][branch]["buildid"]        (classic)
      2) ai["depots"]["branches"][branch]["buildid"]  (like your dump)
    Fallbacks to current_buildid if none found.
    Returns (buildid_or_None, source_str)
    """
    # classic location
    b = ai.get("branches", {})
    if isinstance(b, dict):
        v = b.get(branch)
        if isinstance(v, dict):
            bid = v.get("buildid") or v.get("BuildID") or v.get("BUILDID")
            if bid:
                return str(bid), "branches"

    # under depots/branches (your case)
    dep = ai.get("depots", {})
    if isinstance(dep, dict):
        db = dep.get("branches", {})
        if isinstance(db, dict):
            v = db.get(branch)
            if isinstance(v, dict):
                bid = v.get("buildid") or v.get("BuildID") or v.get("BUILDID")
                if bid:
                    return str(bid), "depots/branches"

    # final fallback
    if current_buildid:
        return str(current_buildid), "fallback: current_buildid"

    return None, "not found"


def get_branch_build_and_depot_manifests(appinfo: dict, appid: str, branch: str, current_buildid: str | None):
    root = appinfo.get(str(appid)) or appinfo.get(appid) or appinfo
    ai = root.get("appinfo", root)

    # NEW: pull buildid from either classic branches or depots/branches
    buildid, buildid_src = _get_buildid(ai, branch, current_buildid)

    # depots → manifests (your existing logic is fine)
    depots = ai.get("depots", {}) or {}
    depot_to_manifest = {}

    def _extract_manifest(v):
        if isinstance(v, dict):
            return v.get("gid") or v.get("GID") or v.get("manifest")
        return v

    for depot_id, depot_info in depots.items():
        if not depot_id.isdigit() or not isinstance(depot_info, dict):
            continue
        manifests = depot_info.get("manifests") or {}
        chosen = None

        if branch in manifests:
            chosen = _extract_manifest(manifests[branch])
        elif branch == "public" and "public" in manifests:
            chosen = _extract_manifest(manifests["public"])
        else:
            # pick newest-looking
            candidates = []
            for k, v in manifests.items():
                gid = _extract_manifest(v)
                if not gid:
                    continue
                tu = None
                if isinstance(v, dict):
                    tu = v.get("timeupdated") or v.get("TimeUpdated")
                    try:
                        tu = int(tu)
                    except Exception:
                        tu = None
                try:
                    gid_num = int(str(gid))
                except Exception:
                    gid_num = 0
                candidates.append((tu if tu is not None else -1, gid_num, str(gid)))
            if candidates:
                candidates.sort(reverse=True)
                chosen = candidates[0][2]

        if chosen:
            depot_to_manifest[depot_id] = str(chosen)

    if not depot_to_manifest:
        raise KeyError("No depot manifests found for selected branch or fallback heuristics.")

    # Optional: debug log where we found the buildid
    print(f"[debug] buildid source: {buildid_src} -> {buildid}")

    return (buildid, depot_to_manifest)

def find_default_steamapps_dir():
    # Common defaults
    plat = sys.platform
    paths = []
    if plat.startswith("win"):
        paths += [
            r"C:\Program Files (x86)\Steam\steamapps",
            r"C:\Program Files\Steam\steamapps",
        ]
    elif plat == "darwin":
        paths += [
            str(Path.home() / "Library/Application Support/Steam/steamapps"),
        ]
    else:
        # Linux
        paths += [
            str(Path.home() / ".local/share/Steam/steamapps"),
            str(Path.home() / ".steam/steam/steamapps"),
        ]
    for p in paths:
        if Path(p).exists():
            return p
    # Fallback to common env var or home
    env = os.environ.get("STEAMAPPS_DIR")
    if env and Path(env).exists():
        return env
    return paths[0] if paths else str(Path.home())

def load_acf(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    return parse_vdf(text)

def save_acf(path: Path, data: dict, backup=True):
    if backup:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(path, path.with_suffix(path.suffix + f".bak.{ts}"))
    path.write_text(dump_vdf(data), encoding="utf-8")
    
def _is_readonly(path: Path) -> bool:
    try:
        return path.exists() and not (os.stat(path).st_mode & stat.S_IWRITE)
    except Exception:
        return False
        
def _set_readonly(path: Path, ro: bool) -> None:
    try:
        mode = os.stat(path).st_mode
        if ro:
            os.chmod(path, (mode & ~stat.S_IWRITE) | stat.S_IREAD)
        else:
            os.chmod(path, mode | stat.S_IWRITE)
    except Exception as e:
        print(f"Warning: could not set read-only={ro} for {path.name}: {e}")
        
def update_appmanifest(appmanifest_path: Path, new_buildid: str | None, depot_to_manifest: dict,
                       dry_run=False):
    data = load_acf(appmanifest_path)
    root_key = "AppState" if "AppState" in data else next(iter(data.keys()))
    appstate = data[root_key]
    changes = []
    
    # enforce StateFlags=4 and ScheduledAutoUpdate=0
    if appstate.get("StateFlags") != "4":
        changes.append(f'StateFlags: {appstate.get("StateFlags")} -> 4')
        if not dry_run:
            appstate["StateFlags"] = "4"
    if appstate.get("ScheduledAutoUpdate") != "0":
        changes.append(f'ScheduledAutoUpdate: {appstate.get("ScheduledAutoUpdate")} -> 0')
        if not dry_run:
            appstate["ScheduledAutoUpdate"] = "0"
    # --- Perform updates ---
    
    if new_buildid:
        old_buildid = appstate.get("buildid")
        if old_buildid != new_buildid:
            changes.append(f"buildid: {old_buildid} -> {new_buildid}")
            if not dry_run:
                appstate["buildid"] = new_buildid

    # depots
    if "InstalledDepots" not in appstate:
        if not changes or dry_run:
            return changes
        elif not dry_run:
            appstate["InstalledDepots"] = {}
    installed = appstate.get("InstalledDepots", {})

    for depot_id, manifest in depot_to_manifest.items():
        if depot_id not in installed:
            continue
        node = installed.get(depot_id, {})
        old = node.get("manifest")
        if old != manifest:
            if not dry_run:
                if depot_id not in installed:
                    installed[depot_id] = {}
                installed[depot_id]["manifest"] = manifest
            changes.append(f"depot {depot_id} manifest: {old} -> {manifest}")
            
    if not changes:
        return changes

    if not dry_run:
        appstate["InstalledDepots"] = installed
        original_readonly = _is_readonly(appmanifest_path)
        if original_readonly:
            try:
                os.chmod(appmanifest_path, os.stat(appmanifest_path).st_mode | stat.S_IWRITE)
            except Exception as e:
                print(f"Warning: could not adjust read-only attribute: {e}")
        save_acf(appmanifest_path, data, backup=False)

        # --- Only restore read-only if it was originally set ---
        if original_readonly:
            try:
                os.chmod(appmanifest_path, stat.S_IREAD)
            except Exception as e:
                print(f"Warning: could not restore read-only attribute: {e}")

    return changes

############################
# Single-app processing    #
############################

def process_one_app(appid: str, appmanifest: Path, args) -> None:
    # establish current buildid for fallback
    current_buildid = None
    try:
        _data = load_acf(appmanifest)
        root_key = "AppState" if "AppState" in _data else next(iter(_data.keys()))
        current_buildid = _data[root_key].get("buildid")
    except Exception:
        pass

    print(f"[{datetime.now().isoformat(timespec='seconds')}] Checking Steam app {appid} (branch: {args.branch}) ...")
    out = run_steamcmd(args.steamcmd, args.username, args.password, appid)
    appinfo = extract_appinfo_dict(out, appid)
    buildid, depot_manifests = get_branch_build_and_depot_manifests(appinfo, appid, args.branch, current_buildid)

    print(f"Latest buildid: {buildid}")
    print(f"Latest depot manifests ({len(depot_manifests)}):")
    for d, m in sorted(depot_manifests.items()):
        print(f"  {d}: {m}")

    changes = update_appmanifest(
        appmanifest,
        buildid,
        depot_manifests,
        dry_run=args.dry_run,
    )
    if changes:
        if args.dry_run:
            print("\nPlanned changes:")
            for c in changes:
                print(" -", c)
        else:
            print("\nUpdated appmanifest with:")
            for c in changes:
                print(" -", c)
    else:
        print("No changes needed; local manifest already matches latest.")
        

def _iter_manifests(steamapps: Path):
    return sorted(steamapps.glob("appmanifest_*.acf"))

def list_manifests(steamapps: Path):
    rows = []
    for p in _iter_manifests(steamapps):
        appid = re.sub(r"^appmanifest_(\d+)\.acf$", r"\1", p.name)
        name = "?"
        try:
            data = load_acf(p)
            root_key = "AppState" if "AppState" in data else next(iter(data.keys()))
            name = data[root_key].get("name") or "?"
        except Exception:
            pass
        ro = " (RO)" if _is_readonly(p) else ""
        rows.append((appid, f"{name}{ro}", p))
    if not rows:
        print(f"No appmanifest_*.acf files found under: {steamapps}")
        return
    width = max(len(appid) for appid, _, _ in rows)
    for appid, name, _ in rows:
        print(f"{appid.rjust(width)}  |  {name}")

def enable_acf(steamapps: Path, appid: str):
    acf = steamapps / f"appmanifest_{appid}.acf"
    bak = steamapps / f"appmanifest_{appid}.acf.bak"
    if not acf.exists():
        print(f"ERROR: {acf} not found.", file=sys.stderr)
        sys.exit(2)
    try:
        # backup (overwrite existing .bak)
        shutil.copy2(acf, bak)
        # set current acf to read-only
        _set_readonly(acf, True)
        print(f"Enabled: backed up to {bak.name} and set {acf.name} read-only.")
    except Exception as e:
        print(f"ERROR enabling {appid}: {e}", file=sys.stderr)
        sys.exit(1)

def disable_acf(steamapps: Path, appid: str):
    acf = steamapps / f"appmanifest_{appid}.acf"
    bak = steamapps / f"appmanifest_{appid}.acf.bak"
    if not bak.exists():
        print(f"ERROR: backup {bak} not found.", file=sys.stderr)
        sys.exit(2)
    try:
        # make sure acf (if exists) is writable, then delete
        if acf.exists():
            if _is_readonly(acf):
                _set_readonly(acf, False)
            acf.unlink()
        # restore bak -> acf
        shutil.move(str(bak), str(acf))
        # ensure restored file is writable
        _set_readonly(acf, False)
        print(f"Disabled: restored {acf.name} from {bak.name}.")
    except Exception as e:
        print(f"ERROR disabling {appid}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Sync local Steam appmanifest to latest build & depot manifests via steamcmd.")
    ap.add_argument("--appid", help="Steam App ID (e.g., 294420)")
    ap.add_argument("--auto", action="store_true",
                    help="Scan the steamapps folder for read-only appmanifest_*.acf files and process each.")
    ap.add_argument("--list", action="store_true",
                    help="List all appmanifest_*.acf with appid and game name.")
    ap.add_argument("--enable", metavar="APPID",
                    help="Backup appmanifest_<APPID>.acf to .acf.bak and set current .acf to read-only.")
    ap.add_argument("--disable", metavar="APPID",
                    help="Restore appmanifest_<APPID>.acf from .acf.bak (deletes current .acf).")
    ap.add_argument("--branch", default="public", help="Steam branch to track (default: public)")
    ap.add_argument("--steamcmd", default="steamcmd", help="Path to steamcmd executable (default: found in PATH)")
    ap.add_argument("--username", default="anonymous", help="Steam username (default: anonymous)")
    ap.add_argument("--password", default=None, help="Steam password (use only if needed)")
    ap.add_argument("--steamapps", default=None, help="Path to steamapps directory (auto-detected if omitted)")
    ap.add_argument("--dry-run", action="store_true", help="Print intended changes without writing the file")

    args = ap.parse_args()

    steamapps = Path(args.steamapps) if args.steamapps else Path(find_default_steamapps_dir())


      
       # Utility commands (no SteamCMD needed)
    if args.list:
        list_manifests(steamapps)
        # fall through; you can combine --list with other actions
    if args.enable:
        enable_acf(steamapps, args.enable)
        return
    if args.disable:
        disable_acf(steamapps, args.disable)
        return
    
        # Validate inputs
    if not args.auto and not args.appid:
        ap.error("You must provide --appid or use --auto.")																												  

    def app_manifest_path_for(appid: str) -> Path:
        return steamapps / f"appmanifest_{appid}.acf"
      
    os.system("taskkill.exe /F /IM steam.exe")
            
    # AUTO MODE
    if args.auto:
        manifest_paths = sorted(steamapps.glob("appmanifest_*.acf"))
        ro_manifests = [p for p in manifest_paths if _is_readonly(p)]
        if not ro_manifests:
            print("No read-only appmanifest_*.acf files found under:", steamapps)
        for p in ro_manifests:
            m = re.match(r"appmanifest_(\d+)\.acf$", p.name)
            if not m:
                continue
            appid = m.group(1)
            try:
                process_one_app(appid, p, args)
            except (VDFParseError, KeyError, subprocess.CalledProcessError) as e:
                print(f"ERROR processing {p.name} (appid {appid}): {e}", file=sys.stderr)

    # SINGLE APP (optional even when --auto is used)
    if args.appid:
        appmanifest = app_manifest_path_for(args.appid)
        if not appmanifest.exists():
            print(f"ERROR: {appmanifest} not found. Use --steamapps to point to the correct Steam library.", file=sys.stderr)
            sys.exit(2)
        try:
            process_one_app(args.appid, appmanifest, args)
        except (VDFParseError, KeyError, subprocess.CalledProcessError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
								  
				 
													
								 
								  
		

if __name__ == "__main__":
    try:
        main()
    except (VDFParseError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
