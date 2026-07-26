"""Push v4 PrivacyHook.m to GitHub using gh default token."""
import subprocess, json, base64

REPO = "sx6427/privacy-hook-ios"
BRANCH = "master"

def get_file_sha(path):
    result = subprocess.run(
        ["gh", "api", f"/repos/{REPO}/contents/{path}?ref={BRANCH}"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return json.loads(result.stdout).get("sha")
    print(f"  get_sha error: {result.stderr[:200]}")
    return None

def update_file(path, content_bytes, message):
    sha = get_file_sha(path)
    if not sha:
        return False
    b64 = base64.b64encode(content_bytes).decode()
    payload = json.dumps({
        "message": message,
        "content": b64,
        "branch": BRANCH,
        "sha": sha
    })
    result = subprocess.run(
        ["gh", "api", "--method", "PUT",
         f"/repos/{REPO}/contents/{path}",
         "--input", "-"],
        input=payload, capture_output=True, text=True
    )
    if result.returncode == 0:
        data = json.loads(result.stdout)
        print(f"  OK {path} commit {data.get('commit',{}).get('sha','?')[:8]}")
    else:
        print(f"  FAIL {path}: {result.stderr[:200]}")
    return result.returncode == 0

print("Updating PrivacyHook.m (v4: payment + jailbreak hiding)...")
with open("PrivacyHook.m", "rb") as f:
    update_file("PrivacyHook.m", f.read(), "v4: payment compat (bundleId spoof, SecCode bypass, jailbreak hiding)")

print("\nDone! GitHub Actions should trigger automatically.")
