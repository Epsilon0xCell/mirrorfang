import json, pathlib, sys
try:
    import yaml
except ImportError:
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parents[1]

def _match_value(actual, expected):
    if isinstance(expected, list):
        return any(_match_value(actual, e) for e in expected)
    return str(actual) == str(expected)

def rule_matches(rule, event):
    """Simple field matching, documented in the README: every selection field
    must match. A field name may end with |contains or |endswith. Values may
    be scalars or lists (any). This is intentionally not a full Sigma engine."""
    selection = rule.get("detection", {}).get("selection", {})
    for field, expected in selection.items():
        if "|" in field:
            name, modifier = field.split("|", 1)
            actual = str(event.get(name, ""))
            if modifier == "contains" and str(expected) not in actual: return False
            elif modifier == "endswith" and not actual.endswith(str(expected)): return False
            elif modifier == "startswith" and not actual.startswith(str(expected)): return False
            elif modifier not in ("contains", "endswith", "startswith"): return False
        else:
            if field not in event: return False
            if not _match_value(event[field], expected): return False
    return True

def load_rule(path):
    if yaml is None:
        raise RuntimeError("PyYAML is required to load Sigma rules")
    return yaml.safe_load(pathlib.Path(path).read_text())

def load_events(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]

def validate_pair(pair_dir):
    pair_dir = pathlib.Path(pair_dir)
    rule = load_rule(pair_dir / "rule.yml")
    attack = load_events(pair_dir / "attack.jsonl")
    benign = load_events(pair_dir / "benign.jsonl")
    attack_fires = [rule_matches(rule, e) for e in attack]
    benign_fires = [rule_matches(rule, e) for e in benign]
    ok = all(attack_fires) and not any(benign_fires)
    return {"pair": pair_dir.name, "attack_fired": attack_fires, "benign_fired": benign_fires, "ok": ok}

def validate_all(root=None):
    pairs_root = pathlib.Path(root) if root else ROOT / "pairs"
    return [validate_pair(d) for d in sorted(pairs_root.iterdir()) if d.is_dir()]

def main():
    results = validate_all()
    failed = 0
    for r in results:
        print(f"{r['pair']}: attack_fired={r['attack_fired']} benign_fired={r['benign_fired']} {'PASS' if r['ok'] else 'FAIL'}")
        if not r["ok"]: failed += 1
    print(f"{len(results)-failed}/{len(results)} pairs pass")
    raise SystemExit(1 if failed else 0)

if __name__ == "__main__":
    main()
