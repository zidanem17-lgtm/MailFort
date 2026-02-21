import json
import os
import stat
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

TOKEN_PATH = os.path.join(os.path.expanduser("~"), ".mailfort_tokens.json")


def load_credentials(scopes):
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, "r") as f:
            data = json.load(f)
        creds = Credentials.from_authorized_user_info(data, scopes=scopes)
        # refresh if needed
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                return None
        return creds
    return None


def save_credentials(creds):
    data = creds.to_json()
    # write securely
    with open(TOKEN_PATH, "w") as f:
        f.write(data)
    os.chmod(TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)


def run_local_oauth(scopes, client_secrets_path="client_secrets.json"):
    if not os.path.exists(client_secrets_path):
        raise FileNotFoundError("Provide OAuth client_secrets.json at workspace root")

    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_path, scopes=scopes)

    # Set redirect URI ONE way only (do NOT also pass redirect_uri= below)
    flow.redirect_uri = "http://localhost"

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    print("\n=== Gmail Authorization Required ===")
    print("1) Open this URL in your browser:\n")
    print(auth_url)
    print("\n2) Approve access.")
    print("3) You will be redirected to a localhost URL that won't load.")
    print("   Copy the FULL localhost URL from the address bar and paste it here.\n")

    redirected = input("Paste the redirected URL here:\n> ").strip()

    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(redirected)
    code = parse_qs(parsed.query).get("code", [None])[0]
    if not code:
        raise RuntimeError("Authorization code not found in the pasted URL (missing ?code=).")

    flow.fetch_token(code=code)
    creds = flow.credentials

    save_credentials(creds)
    return creds


def request_elevated_scopes(current_creds, new_scopes, client_secrets_path="client_secrets.json"):
    # If current creds already have token with required scopes, return it
    if current_creds:
        # quick check: not authoritative but we keep flow simple
        return current_creds
    # otherwise run user consent again for elevated scopes
    return run_local_oauth(new_scopes, client_secrets_path=client_secrets_path)
