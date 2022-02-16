import base64
from pathlib import Path

import webauthn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import validator
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from webauthn.helpers.structs import (
    RegistrationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticationCredential,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)

# secrets.token_hex()
secret_key = "9c580e0641762c32eab407257d924c25d5c8dd44a67d9efb4403038ae783c37c"

middleware = [
    Middleware(
        SessionMiddleware,
        secret_key=secret_key,
        session_cookie="webauthn-demo",
        same_site="strict",
        https_only=True,
    )
]

app = FastAPI(middleware=middleware)


@app.get("/", response_class=HTMLResponse)
async def index():
    # language=HTML
    return """
<h1>Webauthn demo</h1>
<div style="display: flex; justify-content: space-around">
  <div style="border: 1px solid black; padding: 10px">
    <h2>Register</h2>
    <label for="user-id-register">User ID:</label>
    <input type="number" step="1" id="user-id-register"/>
    <button onclick="register()">Register</button>
  </div>
  <div style="border: 1px solid black; padding: 10px">
    <h2>Authenticate</h2>
    <label for="user-id-auth">User ID:</label>
    <input type="number" step="1" id="user-id-auth"/>
    <button onclick="authenticate()">Authenticate</button>
  </div>
</div>
<pre id="log"></pre>
<script src="/webauthn_client.js"></script>
"""


class JavascriptResponse(HTMLResponse):
    media_type = "application/javascript"


@app.get("/webauthn_client.js", response_class=JavascriptResponse)
async def client_js():
    return Path("src/webauthn_client.js").read_bytes()


@app.get("/register/{user_id:int}/", response_model=PublicKeyCredentialCreationOptions)
async def register_get(request: Request, user_id: int):
    public_key = webauthn.generate_registration_options(
        rp_id="localhost",
        rp_name="MyCompanyName",
        user_id=str(user_id),
        user_name=f"{user_id}@example.com",
        user_display_name="Samuel Colvin",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        ),
    )
    request.session["webauthn_register_challenge"] = base64.b64encode(public_key.challenge).decode()
    return public_key


def b64decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


class CustomRegistrationCredential(RegistrationCredential):
    @validator("raw_id", pre=True)
    def convert_raw_id(cls, v: str):
        assert isinstance(v, str), "raw_id is not a string"
        return b64decode(v)

    @validator("response", pre=True)
    def convert_response(cls, data: dict):
        assert isinstance(data, dict), "response is not a dictionary"
        return {k: b64decode(v) for k, v in data.items()}


auth_database = {}


@app.post("/register/{user_id:int}/")
async def register_post(request: Request, user_id: int, credential: CustomRegistrationCredential):
    expected_challenge = base64.b64decode(request.session["webauthn_register_challenge"].encode())
    registration = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
    )
    auth_database[user_id] = {
        "public_key": registration.credential_public_key,
        "sign_count": registration.sign_count,
        "credential_id": registration.credential_id,
    }


@app.get("/auth/{user_id:int}/", response_model=PublicKeyCredentialRequestOptions)
async def auth_get(request: Request, user_id: int):
    try:
        user_creds = auth_database[user_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="user not found")

    public_key = webauthn.generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[PublicKeyCredentialDescriptor(id=user_creds["credential_id"])],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    request.session["webauthn_auth_challenge"] = base64.b64encode(public_key.challenge).decode()
    return public_key


class CustomAuthenticationCredential(AuthenticationCredential):
    @validator("raw_id", pre=True)
    def convert_raw_id(cls, v: str):
        assert isinstance(v, str), "raw_id is not a string"
        return b64decode(v)

    @validator("response", pre=True)
    def convert_response(cls, data: dict):
        assert isinstance(data, dict), "response is not a dictionary"
        return {k: b64decode(v) for k, v in data.items()}


@app.post("/auth/{user_id:int}/")
async def auth_post(request: Request, user_id: int, credential: CustomAuthenticationCredential):
    expected_challenge = base64.b64decode(request.session["webauthn_auth_challenge"].encode())
    try:
        user_creds = auth_database[user_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="user not found")

    auth = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
        credential_public_key=user_creds["public_key"],
        credential_current_sign_count=user_creds["sign_count"],
    )
    debug(auth)
    user_creds["sign_count"] = auth.new_sign_count
