import requests
import re

BASE = 'http://127.0.0.1:5001'
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'adminpass'

sess = requests.Session()

print('Logging in as admin...')
resp = sess.post(f'{BASE}/login', data={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
print('Login HTTP', resp.status_code)

if resp.status_code not in (200, 302):
    print('Login may have failed; check credentials or server.')

print('Adding test permits (admin-only route)')
resp = sess.get(f'{BASE}/admin/add-test-permits')
print('add-test-permits:', resp.status_code)

print('Fetching admin dashboard to find a pending permit id...')
dash = sess.get(f'{BASE}/admin/dashboard')
html = dash.text

# Find first data-id="<number>" occurrence
m = re.search(r'data-id="(\d+)"', html)
if not m:
    print('No permit buttons found in dashboard. HTML length:', len(html))
    exit(1)

pid = m.group(1)
print('Found permit id:', pid)

print('Attempting to approve permit', pid)
res = sess.post(f'{BASE}/admin/approve-permit/{pid}')
print('approve response', res.status_code)
try:
    print(res.json())
except Exception:
    print(res.text[:400])

print('Attempting to reject same permit (should fail or show already approved)')
res2 = sess.post(f'{BASE}/admin/reject-permit/{pid}')
print('reject response', res2.status_code)
try:
    print(res2.json())
except Exception:
    print(res2.text[:400])
