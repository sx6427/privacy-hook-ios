import base64, json, subprocess

with open('.github/workflows/build.yml', 'rb') as f:
    content = base64.b64encode(f.read()).decode()

payload = json.dumps({
    'message': 'Add build workflow',
    'content': content,
    'branch': 'master'
})

result = subprocess.run([
    'gh', 'api',
    '--method', 'PUT',
    '/repos/sx6427/privacy-hook-ios/contents/.github/workflows/build.yml',
    '--input', '-'
], input=payload, capture_output=True, text=True)

print('STDOUT:', result.stdout[:500] if result.stdout else '(empty)')
print('STDERR:', result.stderr[:500] if result.stderr else '(empty)')
print('Return code:', result.returncode)
