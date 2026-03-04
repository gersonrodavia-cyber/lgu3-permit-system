import re
import requests

BASE = 'http://127.0.0.1:5001'
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'adminpass'

sess = requests.Session()

print('Logging in as admin to prepare test user...')
resp = sess.post(f'{BASE}/login', data={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
print('Admin login:', resp.status_code)

# Create a test user via signup
user_email = 'testuser@example.com'
user_password = 'testpass'
print('Creating test user (signup)')
resp = sess.post(f'{BASE}/signup', data={
    'first_name': 'Test', 'last_name': 'User', 'business_name': 'TestBiz',
    'email': user_email, 'password': user_password
})
print('Signup HTTP', resp.status_code)

# Logout admin, login as test user
sess.get(f'{BASE}/logout')
print('Logging in as test user...')
resp = sess.post(f'{BASE}/login', data={'email': user_email, 'password': user_password})
print('User login HTTP', resp.status_code)

# Submit a simple business registration
print('Submitting a simple business registration...')
resp = sess.post(f'{BASE}/register_business_simple', data={'business_name': 'My Test Shop', 'address': '123 Main St'})
print('Submit status', resp.status_code)

# Go to user dashboard businesses
dash = sess.get(f'{BASE}/dashboard/businesses')
print('User dashboard businesses HTTP', dash.status_code)
if 'My Test Shop' in dash.text:
    print('Business appears in user dashboard (pending).')
else:
    print('Business not found in user dashboard; HTML length:', len(dash.text))

# Logout test user and login as admin to approve
sess.get(f'{BASE}/logout')
print('Logging back in as admin...')
resp = sess.post(f'{BASE}/login', data={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
print('Admin login:', resp.status_code)

# Find the business id from admin/businesses page
adm = sess.get(f'{BASE}/admin/businesses')
m = re.search(r'href="/approve/(\d+)"', adm.text)
if not m:
    print('Could not find pending business on admin page; length', len(adm.text))
    exit(1)

bid = m.group(1)
print('Found pending business id:', bid)

print('Approving business', bid)
resp = sess.get(f'{BASE}/approve/{bid}')
print('Approve status', resp.status_code)

# Check user dashboard again
sess.get(f'{BASE}/logout')
sess.post(f'{BASE}/login', data={'email': user_email, 'password': user_password})
dash2 = sess.get(f'{BASE}/dashboard/businesses')
if '🟢 Approved' in dash2.text:
    print('User dashboard shows approved state — success!')
else:
    print('User dashboard did not show approved state. HTML length:', len(dash2.text))
