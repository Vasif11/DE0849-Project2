#!/usr/bin/env python3
"""Selenium runtime/authentication validation against Juice Shop (Scenario B, Phase 2B).

Drives a real browser on the remote Selenium Grid, performs a login, and verifies the resulting
authenticated runtime state (localStorage token, cookies). Produces structured JSON evidence and
an authenticated screenshot.

Outputs:
  security/selenium/evidence/juice-shop-auth-storage.json
  security/selenium/evidence/juice-shop-authenticated.png

Exit code 0 only if the authenticated state is reached (login_success and token_present).
"""
import json
import os
import sys
import time
import urllib.request

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

GRID = os.environ.get("SELENIUM_URL", "http://10.20.10.30:4444")
TARGET = os.environ.get("JUICE_URL", "http://10.20.10.20:3000")
RUN_ID = os.environ.get("RUN_ID", time.strftime("%Y%m%d-%H%M%S"))
EVIDENCE = os.path.dirname(os.path.abspath(__file__)) + "/evidence"
os.makedirs(EVIDENCE, exist_ok=True)

EMAIL = f"ci-user-{RUN_ID}@test.local"
PASSWORD = "CiUserPass1!"


def try_register():
    """Register a normal user through the REST API; return True on success."""
    body = json.dumps({"email": EMAIL, "password": PASSWORD, "passwordRepeat": PASSWORD,
                       "securityQuestion": {"id": 1}, "securityAnswer": "ci"}).encode()
    req = urllib.request.Request(f"{TARGET}/api/Users", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status in (200, 201)
    except Exception as e:
        print(f"[selenium] registration via REST failed ({e}); will use SQLi bypass login")
        return False


def main():
    registered = try_register()
    login_email = EMAIL if registered else "' OR 1=1--"   # fall back to the SQLi auth bypass
    login_pw = PASSWORD if registered else "x"

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1280,900")
    driver = webdriver.Remote(command_executor=GRID, options=opts)
    result = {"run_id": RUN_ID, "target": TARGET, "grid": GRID,
              "login_method": "registered-user" if registered else "sqli-bypass",
              "login_email": login_email, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}
    def dismiss_overlays():
        # Juice Shop shows a welcome dialog and a cookie-consent bar that intercept clicks.
        for by, sel in [(By.CSS_SELECTOR, "button[aria-label='Close Welcome Banner']"),
                        (By.CSS_SELECTOR, "a.cc-btn.cc-dismiss"),
                        (By.CSS_SELECTOR, "button[aria-label='dismiss cookie message']")]:
            try:
                for el in driver.find_elements(by, sel):
                    driver.execute_script("arguments[0].click();", el)
            except Exception:
                pass

    try:
        wait = WebDriverWait(driver, 30)
        driver.get(f"{TARGET}/#/login")
        time.sleep(3)
        dismiss_overlays()
        wait.until(EC.presence_of_element_located((By.ID, "email")))
        driver.find_element(By.ID, "email").send_keys(login_email)
        driver.find_element(By.ID, "password").send_keys(login_pw)
        dismiss_overlays()
        # JS click bypasses any residual overlay intercept
        driver.execute_script("arguments[0].click();", driver.find_element(By.ID, "loginButton"))

        # authenticated state: Juice Shop stores the JWT in localStorage under 'token'
        token = None
        for _ in range(30):
            token = driver.execute_script("return window.localStorage.getItem('token');")
            if token:
                break
            time.sleep(1)

        storage_keys = driver.execute_script(
            "return Object.keys(window.localStorage);") or []
        cookies = [{"name": c["name"], "secure": c.get("secure"), "httpOnly": c.get("httpOnly")}
                   for c in driver.get_cookies()]
        driver.get(f"{TARGET}/#/")
        time.sleep(2)
        driver.save_screenshot(f"{EVIDENCE}/juice-shop-authenticated.png")

        result.update({
            "login_success": bool(token),
            "token_present": bool(token),
            "token_prefix": (token[:16] + "...") if token else None,
            "localStorage_keys": storage_keys,
            "cookies": cookies,
            "screenshot": "juice-shop-authenticated.png",
        })
    finally:
        driver.quit()

    with open(f"{EVIDENCE}/juice-shop-auth-storage.json", "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("login_success") and result.get("token_present") else 1)


if __name__ == "__main__":
    main()
