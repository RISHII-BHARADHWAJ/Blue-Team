"""Adversarial HTTP checks against disposable CI only; no external targets."""
import http.cookiejar, urllib.request, urllib.error, re
base = 'http://127.0.0.1:8080/'
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def request(path, data=None):
    try:
        with client.open(base+path, data=data, timeout=15) as r: return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), e.headers
for path in ['.git/config','.git/HEAD','.env','.env.local','.github/workflows/ci.yml',
             'database.sql','includes/config.php','tests/security_regression.php','deploy/php-security.ini']:
    status,body,headers=request(path)
    assert status == 403, (path,status)
for path in ['live_status.php','api/v1/incidents.php','api/v1/approval_queue.php']:
    assert request(path)[0] == 401, path
status,body,headers=request('login.php')
assert status == 200
assert headers['X-Frame-Options'] == 'DENY'
assert headers['X-Content-Type-Options'] == 'nosniff'
assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
assert 'X-Powered-By' not in headers
assert request('login.php',b'csrf_token[]=invalid&username=admin&password=x')[0] == 403
token=re.search(r'name="csrf_token" value="([a-f0-9]+)"',body)[1]
assert request('login.php',('csrf_token='+token+'&username[]=admin&password=x').encode())[0] == 400
assert request('logout.php',b'csrf_token[]=invalid')[0] == 403
status,body,_=request('login.php',('csrf_token='+token+"&username=%27+OR+1%3D1--&password=x").encode())
assert status == 200 and 'Invalid credentials.' in body
assert request('api/v1/incidents.php')[0] == 401
assert request('login.php',b'x=' + b'a'*1048576)[0] == 413
print('PASS: protected files, anonymous APIs, cookie/response headers, malformed forms, logout CSRF, login SQL injection, request size')
