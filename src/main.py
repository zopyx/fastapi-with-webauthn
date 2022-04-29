import base64
import os
import pickle
from pathlib import Path

import webauthn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import validator
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialType,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
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
    with open("src/index.html") as fh:
        # language=HTML
        return fh.read()


class CSSResponse(HTMLResponse):
    media_type = "text/css"


class JavascriptResponse(HTMLResponse):
    media_type = "application/javascript"


@app.get("/webauthn_client.js", response_class=JavascriptResponse)
async def client_js():
    return Path("src/webauthn_client.js").read_bytes()


@app.get("/styles.css", response_class=CSSResponse)
async def client_css():
    return Path("src/styles.css").read_bytes()


ATTESTATION_TYPE_MAPPING = {
    "none": AttestationConveyancePreference.NONE,
    "indirect": AttestationConveyancePreference.INDIRECT,
    "direct": AttestationConveyancePreference.DIRECT,
}


AUTH_MAPPING = {
    "cross-platform": AuthenticatorAttachment.CROSS_PLATFORM,
    "platform": AuthenticatorAttachment.PLATFORM,
}


@app.get("/register/{user_id:str}/", response_model=PublicKeyCredentialCreationOptions)
async def register_get(request: Request, user_id: str, attestation_type: str, authenticator_type: str):
    public_key = webauthn.generate_registration_options(
        rp_id="localhost",
        rp_name="MyCompanyName",
        user_id=user_id,
        user_name=f"{user_id}@example.com",
        user_display_name="Samuel Colvin",
        attestation=ATTESTATION_TYPE_MAPPING[attestation_type],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AUTH_MAPPING[authenticator_type]
            if authenticator_type
            else AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    request.session["webauthn_register_challenge"] = base64.b64encode(public_key.challenge).decode()
    return public_key


def b64decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


class CustomRegistrationCredential(RegistrationCredential):
    @validator("raw_id", pre=True)
    def convert_raw_id(self, v: str):
        assert isinstance(v, str), "raw_id is not a string"
        return b64decode(v)

    @validator("response", pre=True)
    def convert_response(self, data: dict):
        assert isinstance(data, dict), "response is not a dictionary"
        return {k: b64decode(v) for k, v in data.items()}


auth_database = {}
with open("src/pickle_file", "rb") as file:
    if os.stat("src/pickle_file").st_size != 0:
        auth_database = pickle.load(file)


@app.post("/register/{user_id:str}/")
async def register_post(request: Request, user_id: str, credential: CustomRegistrationCredential):
    expected_challenge = base64.b64decode(request.session["webauthn_register_challenge"].encode())
    registration = webauthn.verify_registration_response(  # type: ignore
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
    )
    auth_database[user_id] = {
        "public_key": registration.credential_public_key,
        "sign_count": registration.sign_count,
        "credential_id": registration.credential_id,
        "challenge": expected_challenge,
    }

    with open("src/pickle_file", "wb") as fh:
        pickle.dump(auth_database, fh)


@app.get("/auth/{user_id:str}/", response_model=PublicKeyCredentialRequestOptions)
async def auth_get(request: Request, user_id: str, attestation_type: str, authenticator_type: str):
    try:
        user_creds = auth_database[user_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="user not found")

    public_key = webauthn.generate_authentication_options(  # type: ignore
        rp_id="localhost",
        timeout=50000,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=user_creds["credential_id"],
            )
        ],
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    request.session["webauthn_auth_challenge"] = base64.b64encode(public_key.challenge).decode()
    return public_key


class CustomAuthenticationCredential(AuthenticationCredential):
    @validator("raw_id", pre=True)
    def convert_raw_id(self, v: str):
        assert isinstance(v, str), "raw_id is not a string"
        return b64decode(v)

    @validator("response", pre=True)
    def convert_response(self, data: dict):
        assert isinstance(data, dict), "response is not a dictionary"
        return {k: b64decode(v) for k, v in data.items()}


@app.post("/auth/{user_id:str}/")
async def auth_post(request: Request, user_id: str, credential: CustomAuthenticationCredential):
    expected_challenge = base64.b64decode(request.session["webauthn_auth_challenge"].encode())
    try:
        user_creds = auth_database[user_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="user not found")

    auth = webauthn.verify_authentication_response(  # type: ignore
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8000",
        credential_public_key=user_creds["public_key"],
        credential_current_sign_count=user_creds["sign_count"],
    )
    user_creds["sign_count"] = auth.new_sign_count
