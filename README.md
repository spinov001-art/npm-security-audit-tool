# npm Security Audit Tool 🔒

Check any npm package for known vulnerabilities before you install it. Uses npm's free Security Advisory API — no API key needed.

## Why?

Supply chain attacks on npm are increasing. Before adding a dependency, check if it has known vulnerabilities.

## Quick Start

```bash
pip install requests
python npm_audit.py express
python npm_audit.py --check-all package.json
```

## How It Works

npm has a free bulk advisory endpoint at `registry.npmjs.org/-/npm/v1/security/advisories/bulk`.

```python
import requests

def audit_package(package_name):
    """Check a single npm package for known vulnerabilities."""
    url = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
    payload = {package_name: ["*"]}
    resp = requests.post(url, json=payload, timeout=10)
    advisories = resp.json()
    if not advisories:
        print(f"✅ {package_name}: No known vulnerabilities")
        return []
    vulns = []
    for pkg, items in advisories.items():
        for item in items:
            vulns.append({
                "package": pkg,
                "severity": item.get("severity", "unknown"),
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "vulnerable_versions": item.get("vulnerable_versions", "")
            })
    print(f"⚠️  {package_name}: {len(vulns)} vulnerabilities found")
    for v in vulns:
        print(f"   [{v['severity'].upper()}] {v['title']}")
    return vulns

# Example
audit_package("lodash")
audit_package("express")
```

## Audit package.json Dependencies

```python
import json

def audit_package_json(filepath):
    """Audit all dependencies in a package.json file."""
    with open(filepath) as f:
        pkg = json.load(f)

    deps = {}
    for name, version in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
        deps[name] = [version.lstrip("^~>=<")]

    url = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
    resp = requests.post(url, json=deps, timeout=30)
    advisories = resp.json()

    total = sum(len(v) for v in advisories.values())
    print(f"\nScanned {len(deps)} packages, found {total} advisories\n")

    for pkg_name, items in advisories.items():
        for item in items:
            sev = item.get("severity", "?").upper()
            print(f"  [{sev}] {pkg_name}: {item.get('title', '')}")

    return advisories

# Usage: audit_package_json("package.json")
```

## Get Package Metadata

```python
def get_package_info(name):
    """Get metadata for any npm package — no API key needed."""
    resp = requests.get(f"https://registry.npmjs.org/{name}", timeout=10)
    data = resp.json()
    latest = data.get("dist-tags", {}).get("latest", "?")
    return {
        "name": name,
        "version": latest,
        "description": data.get("description", ""),
        "weekly_downloads": get_downloads(name),
        "license": data.get("license", "unknown"),
        "homepage": data.get("homepage", ""),
    }

def get_downloads(name):
    resp = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=5)
    return resp.json().get("downloads", 0)

info = get_package_info("express")
print(f"{info['name']} v{info['version']} — {info['weekly_downloads']:,} weekly downloads")
```

## Scale with Apify

For production scanning (bulk audits, CI/CD integration, scheduled monitoring):

🔗 **[npm Package Scraper on Apify](https://apify.com/knotless_cadence/npm-package-scraper)** — Cloud-hosted, handles rate limits, exports to JSON/CSV.

## More Tools

- [Reddit Data Analysis](https://github.com/spinov001-art/reddit-data-analysis-python)
- [HN Trends Tracker](https://github.com/spinov001-art/hacker-news-trends-python)
- [Awesome Web Scraping 2026](https://github.com/spinov001-art/awesome-web-scraping-2026) — 77+ free data tools
- [Python Supply Chain Scanner](https://github.com/spinov001-art/python-supply-chain-scanner)

## Need Custom Security Auditing?

**[Hire me →](https://spinov001-art.github.io)** | Email: Spinov001@gmail.com

## License

MIT
