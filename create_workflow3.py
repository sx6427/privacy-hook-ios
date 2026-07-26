"""
Create workflow file via GitHub Git Data API using direct HTTP requests.
"""
import subprocess, json, base64, sys, urllib.request, ssl

REPO = "sx6427/privacy-hook-ios"
BRANCH = "master"

# Get token from gh CLI
token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()
if not token:
    print("ERROR: Cannot get GitHub token", file=sys.stderr)
    sys.exit(1)

ctx = ssl.create_default_context()

def api_call(method, path, payload=None):
    url = f"https://api.github.com/repos/{REPO}/{path}"
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "privacy-hook-build")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = resp.read().decode()
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return None

# 1. Read workflow content
with open(".github/workflows/build.yml", "rb") as f:
    workflow_content = f.read()

print("[1/6] Creating blob...")
blob = api_call("POST", "git/blobs", {
    "content": base64.b64encode(workflow_content).decode(),
    "encoding": "base64"
})
if not blob:
    sys.exit(1)
print(f"  Blob SHA: {blob['sha']}")

# 2. Get branch ref
print("[2/6] Getting branch ref...")
ref = api_call("GET", f"git/refs/heads/{BRANCH}")
if not ref:
    sys.exit(1)
commit_sha = ref["object"]["sha"]
print(f"  Commit: {commit_sha}")

# 3. Get tree SHA
print("[3/6] Getting commit tree...")
commit = api_call("GET", f"git/commits/{commit_sha}")
if not commit:
    sys.exit(1)
tree_sha = commit["tree"]["sha"]
print(f"  Tree: {tree_sha}")

# 4. Create new tree
print("[4/6] Creating new tree...")
new_tree = api_call("POST", "git/trees", {
    "base_tree": tree_sha,
    "tree": [{
        "path": ".github/workflows/build.yml",
        "mode": "100644",
        "type": "blob",
        "sha": blob["sha"]
    }]
})
if not new_tree:
    sys.exit(1)
print(f"  New tree: {new_tree['sha']}")

# 5. Create commit
print("[5/6] Creating commit...")
new_commit = api_call("POST", "git/commits", {
    "message": "Add build workflow",
    "tree": new_tree["sha"],
    "parents": [commit_sha]
})
if not new_commit:
    sys.exit(1)
print(f"  Commit: {new_commit['sha']}")

# 6. Update ref
print("[6/6] Updating branch ref...")
result = api_call("PATCH", f"git/refs/heads/{BRANCH}", {
    "sha": new_commit["sha"],
    "force": False
})
if not result:
    sys.exit(1)

print(f"\n✅ Workflow created! Commit: {new_commit['sha'][:8]}")
print("GitHub Actions should start building now.")
