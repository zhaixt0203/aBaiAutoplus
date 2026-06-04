#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "gopay-auto-protocol"
RELEASE = ROOT / "release" / "gopay-web-smscode-preview"
sys.path.insert(0, str(RELEASE))
sys.path.insert(0, str(PROTOCOL))

from gopay_protocol import AUTH, CUSTOMER, DeviceProfile, EnhancedPythonXESigner, GoPayProtocol, normalize_id_phone, pick_first  # noqa: E402
from smscode_client import SmsCodeGG  # noqa: E402


def save_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def masked_phone(value: str) -> str:
    value = str(value or "")
    return value[:5] + "..." + value[-4:] if len(value) > 10 else value


def extract_account_id(data: Any) -> str:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in {"account_id", "accountid", "customer_id", "userid", "user_id", "id"}:
                    if re.fullmatch(r"\d{5,20}", str(child or "")):
                        found.append(str(child))
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found[0] if found else ""


def login_with_known_pin(gp: GoPayProtocol, phone: str, pin: str) -> tuple[str, str]:
    country_code, local = normalize_id_phone(phone)
    sc, data, _ = gp.login_methods(local, country_code)
    print(f"[账号] PIN 登录：查询方式 -> HTTP {sc}")
    if sc not in (200, 201, 202):
        return "", ""
    verification_id = str(pick_first(data, ["verification_id", "challenge_id"]) or "")
    sc, data, _ = gp.cvs_initiate(
        local,
        verification_id,
        method="goto_pin",
        flow="login_1fa",
        country_code=country_code,
    )
    print(f"[账号] PIN 登录：创建挑战 -> HTTP {sc}")
    if sc not in (200, 201, 202, 204):
        print(f"[账号] PIN 登录失败详情：{json.dumps(data, ensure_ascii=False)[:800]}")
        return "", ""
    challenge_id = str(pick_first(data, ["challenge_id", "challengeId"]) or "")
    sc, data, _ = gp.post(
        CUSTOMER,
        "/api/v1/users/pin/tokens/nb",
        {
            "challenge_id": challenge_id,
            "client_id": "6d11d261d7ae462dbd4be0dc5f36a697-MFAGOJEK",
            "pin": pin,
        },
    )
    print(f"[账号] PIN 登录：验证 PIN -> HTTP {sc}")
    if sc not in (200, 201, 202):
        print(f"[账号] PIN 登录失败详情：{json.dumps(data, ensure_ascii=False)[:800]}")
        return "", ""
    pin_token = str(pick_first(data, ["token"]) or "")
    sc, data, _ = gp.post(
        AUTH,
        "/cvs/v1/verify",
        {
            "client_id": gp.client_id,
            "client_secret": gp.client_secret,
            "data": {"challenge_id": challenge_id, "validation_jwt": pin_token},
            "flow": "login_1fa",
            "verification_id": verification_id,
            "verification_method": "goto_pin",
        },
    )
    print(f"[账号] PIN 登录：确认挑战 -> HTTP {sc}")
    if sc not in (200, 201, 202):
        print(f"[账号] PIN 登录失败详情：{json.dumps(data, ensure_ascii=False)[:800]}")
        return "", ""
    verification_token = str(pick_first(data, ["verification_token", "verificationToken"]) or "")
    sc, data, _ = gp.accountlist(verification_token)
    print(f"[账号] PIN 登录：读取账号 -> HTTP {sc}")
    if sc not in (200, 201, 202):
        return "", ""
    account_id = extract_account_id(data)
    one_fa_token = str(pick_first(data, ["1fa_token", "one_fa_token", "token"]) or "")
    sc, data, _ = gp.token(verification_token=one_fa_token, account_id=account_id)
    print(f"[账号] PIN 登录：获取登录状态 -> HTTP {sc}")
    if sc not in (200, 201, 202):
        return "", ""
    return (
        str(pick_first(data, ["access_token", "accessToken"]) or ""),
        str(pick_first(data, ["refresh_token", "refreshToken"]) or ""),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Rebind a mature GoPay account to an active SMSCode number")
    ap.add_argument("--accounts-json", required=True)
    ap.add_argument("--account-index", type=int, default=0)
    ap.add_argument("--order-id", required=True)
    ap.add_argument("--new-phone", required=True, help="E.164 phone, e.g. +628...")
    ap.add_argument("--email", default="", help="换绑时同步提交的邮箱；留空时自动生成测试邮箱")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default="")
    ap.add_argument("--reference-device-profile", action="store_true", help="按参考项目原规则重建成熟账号的原始设备身份")
    args = ap.parse_args()

    loaded_accounts = json.loads(pathlib.Path(args.accounts_json).read_text(encoding="utf-8-sig"))
    accounts = loaded_accounts if isinstance(loaded_accounts, list) else [loaded_accounts.get("account", loaded_accounts)]
    account = dict(accounts[args.account_index])
    cfg = json.loads((RELEASE / "config.json").read_text(encoding="utf-8-sig"))
    sms = SmsCodeGG(str(cfg["smscode_token"]), logger=lambda msg: print(f"[SMSCode] {msg}"))
    if args.reference_device_profile:
        ref_src = ROOT / "参考项目" / "aBaiAutoplus-main" / "aBaiAutoplus-main" / "platforms" / "gopay-deploy" / "app" / "src"
        sys.path.insert(0, str(ref_src))
        from opai.core.gopay_app_protocol import build_device_profile

        device = build_device_profile(str(account.get("phone") or ""))
        print("[账号] 已按原始规则恢复设备身份")
    else:
        device = DeviceProfile.default(template_name=str(cfg.get("device_template") or "oppo-reno12f"))
    gp = GoPayProtocol(device=device, signer=EnhancedPythonXESigner(), debug=False, proxy=str(cfg.get("proxy") or "") or None)
    out = pathlib.Path(args.out) if args.out else ROOT / "data" / "rebound-accounts" / f"{args.order_id}.json"
    result: dict[str, Any] = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_registered_at": account.get("registered_at"),
        "source_phone": account.get("phone"),
        "new_phone": args.new_phone,
        "order_id": str(args.order_id),
        "account_index": args.account_index,
    }

    try:
        print(f"[账号] 使用成熟账号 {masked_phone(str(account.get('phone') or ''))}，注册时间={account.get('registered_at')}")
        sc, data, _ = gp.token(refresh_token=str(account.get("refresh_token") or ""), account_id="")
        print(f"[账号] 刷新登录状态 -> HTTP {sc}")
        if sc not in (200, 201, 202):
            print("[账号] 刷新失败，按参考项目逻辑继续尝试旧登录状态")
        access_token = str(
            (pick_first(data, ["access_token", "accessToken"]) if sc in (200, 201, 202) else "")
            or account.get("access_token")
            or ""
        )
        refresh_token = str(
            (pick_first(data, ["refresh_token", "refreshToken"]) if sc in (200, 201, 202) else "")
            or account.get("refresh_token")
            or ""
        )
        if sc not in (200, 201, 202):
            pin_access, pin_refresh = login_with_known_pin(
                gp,
                str(account.get("phone") or ""),
                str(account.get("pin") or ""),
            )
            access_token = pin_access or access_token
            refresh_token = pin_refresh or refresh_token
        if not access_token:
            result.update({"success": False, "stage": "refresh_token", "detail": "missing access_token"})
            save_json(out, result)
            return 2

        sc, data, _ = gp.customers_update_phone(
            access_token,
            new_phone=args.new_phone,
            pin=str(account.get("pin") or ""),
            email=str(args.email or f"gopay_auto_plus_{args.order_id}@gmail.com"),
        )
        print(f"[换绑] 发起更换号码 -> HTTP {sc}")
        if sc not in (200, 201, 202):
            result.update({"success": False, "stage": "customers_update_phone", "status": sc, "response": data})
            save_json(out, result)
            return 3
        otp_token = str(pick_first(data, ["otp_token", "otpToken"]) or "")
        if not otp_token:
            result.update({"success": False, "stage": "customers_update_phone", "detail": "missing otp_token", "response": data})
            save_json(out, result)
            return 3

        code, raw = sms.poll_code(str(args.order_id), timeout=args.timeout, interval=3)
        print(f"[SMSCode] 已收到换绑验证码，状态={raw.get('status')}")
        sc, data, _ = gp.customers_verify_update(access_token, code, otp_token)
        print(f"[换绑] 确认新号码 -> HTTP {sc}")
        if sc not in (200, 201, 202):
            result.update({"success": False, "stage": "customers_verify_update", "status": sc, "response": data})
            save_json(out, result)
            return 4

        result.update(
            {
                "success": True,
                "stage": "complete",
                "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "account": {
                    **account,
                    "phone": args.new_phone,
                    "local": args.new_phone.removeprefix("+62"),
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
            }
        )
        save_json(out, result)
        print(f"[完成] 成熟账号已更换到新号码 {masked_phone(args.new_phone)}")
        print(f"[完成] 保存位置：{out}")
        return 0
    finally:
        gp.close()


if __name__ == "__main__":
    raise SystemExit(main())
