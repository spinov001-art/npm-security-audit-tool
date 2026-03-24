"""
npm Security Audit Tool - Check packages for vulnerabilities.
Uses npm's free Security Advisory API. No API key needed.

Usage:
    python npm_audit.py express lodash axios
    python npm_audit.py --check-all package.json
    python npm_audit.py --info react
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_ADVISORY = f"{NPM_REGISTRY}/-/npm/v1/security/advisories/bulk"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"


def audit_packages(packages):
    """Check multiple packages for vulnerabilities."""
    payload = {pkg: ["*"] for pkg in packages}
    resp = requests.post(NPM_ADVISORY, json=payload, timeout=15)
    advisories = resp.json()

    results = {}
    for pkg in packages:
        if pkg in advisories:
            vulns = []
            for item in advisories[pkg]:
                vulns.append({
                    "severity": item.get("severity", "unknown"),
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "vulnerable_versions": item.get("vulnerable_versions", ""),
                    "patched_versions": item.get("patched_versions", ""),
                })
            results[pkg] = vulns
        else:
            results[pkg] = []

    return results


def audit_package_json(filepath):
    """Audit all deps in package.json."""
    with open(filepath) as f:
        pkg = json.load(f)

    all_deps = {}
    for section in ["dependencies", "devDependencies", "peerDependencies"]:
        all_deps.update(pkg.get(section, {}))

    if not all_deps:
        print("No dependencies found")
        return {}

    return audit_packages(list(all_deps.keys()))


def get_package_info(name):
    """Get package metadata from npm registry."""
    resp = requests.get(f"{NPM_REGISTRY}/{name}", timeout=10)
    if resp.status_code == 404:
        return None
    data = resp.json()
    latest = data.get("dist-tags", {}).get("latest", "?")
    latest_data = data.get("versions", {}).get(latest, {})

    dl = requests.get(f"{NPM_DOWNLOADS}/{name}", timeout=5)
    downloads = dl.json().get("downloads", 0) if dl.ok else 0

    return {
        "name": name,
        "version": latest,
        "description": data.get("description", ""),
        "license": latest_data.get("license", "unknown"),
        "weekly_downloads": downloads,
        "homepage": data.get("homepage", ""),
        "dependencies": len(latest_data.get("dependencies", {})),
        "maintainers": len(data.get("maintainers", [])),
    }


def print_results(results):
    """Pretty-print audit results."""
    total_vulns = sum(len(v) for v in results.values())
    clean = sum(1 for v in results.values() if not v)

    print(f"\nScanned {len(results)} packages: {clean} clean, {len(results) - clean} with issues")
    print(f"Total vulnerabilities: {total_vulns}\n")

    for pkg, vulns in sorted(results.items()):
        if not vulns:
            print(f"  OK  {pkg}")
        else:
            print(f"  !!  {pkg} ({len(vulns)} vulnerabilities)")
            for v in vulns:
                sev = v["severity"].upper()
                print(f"      [{sev:>8}] {v['title']}")
                if v.get("patched_versions"):
                    print(f"               Fix: upgrade to {v['patched_versions']}")


def main():
    parser = argparse.ArgumentParser(description="Audit npm packages for vulnerabilities")
    parser.add_argument("packages", nargs="*", help="Package names to audit")
    parser.add_argument("--check-all", metavar="FILE", help="Audit all deps in package.json")
    parser.add_argument("--info", metavar="PKG", help="Get package metadata")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.info:
        info = get_package_info(args.info)
        if not info:
            print(f"Package '{args.info}' not found")
            sys.exit(1)
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            print(f"{info['name']} v{info['version']}")
            print(f"  {info['description']}")
            print(f"  Downloads: {info['weekly_downloads']:,}/week")
            print(f"  License: {info['license']}")
            print(f"  Dependencies: {info['dependencies']}")
        return

    if args.check_all:
        results = audit_package_json(args.check_all)
    elif args.packages:
        results = audit_packages(args.packages)
    else:
        parser.print_help()
        return

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results)


if __name__ == "__main__":
    main()
