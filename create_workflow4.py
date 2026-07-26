"""Create workflow file via Contents API using new token with workflow scope."""
import subprocess, json, base64, sys, os

os.environ["GH_TOKEN"] = "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"
REPO = "sx6427/privacy-hook-ios"

with open(".github/workflows/build.yml", "rb") as f:
    content = base64.b64encode(f.read()).decode()

payload = json.dumps({
    "message": "Add build workflow",
    "content": content,
    "branch": "master"
})

result = subprocess.run(
    ["gh", "api", "--method", "PUT",
     f"/repos/{REPO}/contents/.github/workflows/build.yml",
     "--input", "-"],
    input=payload, capture_output=True, text=True
)

print("Return code:", result.returncode)
if result.stdout:
    data = json.loads(result.stdout)
    print("Commit:", data.get("commit", {}).get("sha", "unknown")[:8])
    print("Message:", data.get("commit", {}).get("message", ""))
if result.stderr:
    print("Error:", result.stderr[:300])
