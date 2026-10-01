"""
Automated Streamlit keep-alive and wake-up sentinel using Playwright.
Simulates a real browser visit, executes JavaScript, establishes WebSocket
connections, and clicks the wake-up button if hibernated.
"""

import sys
import time
from playwright.sync_api import sync_playwright

DEFAULT_TARGET_URL = "https://pedas2026-pandi-radar.streamlit.app"
PAGE_TIMEOUT_MS = 60000
RENDER_TIMEOUT_MS = 45000
IDLE_WAIT_SECONDS = 8


def wake_dashboard(target_url: str) -> None:
    print(f"Launching headless browser to inspect: {target_url}")
    with sync_playwright() as playwright_instance:
        browser = playwright_instance.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800}
        )
        page = context.new_page()

        try:
            print("Navigating to URL...")
            response = page.goto(target_url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded")
            http_status = response.status if response is not None else 0
            print(f"Initial HTTP response: {http_status}")

            # Check if Streamlit sleep / hibernation screen is present
            wake_selectors = [
                "button:has-text('get this app back up')",
                "button:has-text('Wake app back up')",
                "button:has-text('Yes, get this app back up')",
                "button:has-text('Wake')"
            ]
            
            button_clicked = False
            for selector in wake_selectors:
                locator = page.locator(selector)
                if locator.count() > 0 and locator.first.is_visible():
                    print(f"Detected hibernation wake button with selector '{selector}'. Clicking...")
                    locator.first.click()
                    button_clicked = True
                    print("Wake button clicked. Waiting 12 seconds for container boot...")
                    page.wait_for_timeout(12000)
                    break

            if not button_clicked:
                print("No sleep screen detected. Verifying active Streamlit WebSocket and DOM container...")

            # Confirm app render via multiple robust locators (header, text, container, or iframe)
            app_indicator = page.locator(
                "h1, text='PANDI ccTLD', [data-testid='stAppViewContainer'], [data-testid='stApp'], iframe[title='streamlitApp']"
            )
            app_indicator.first.wait_for(timeout=RENDER_TIMEOUT_MS)
            print("Streamlit dashboard rendered successfully!")

            # Keep connection open to let the WebSocket handshake register active telemetry
            print(f"Holding session open for {IDLE_WAIT_SECONDS} seconds...")
            time.sleep(IDLE_WAIT_SECONDS)

            page_title = page.title()
            print(f"Page title confirmed: {page_title}")
            print("Keep-alive successful: WebSocket session established and active.")

        except Exception as error:
            print(f"Sentinel warning or failure during page inspection: {error}")
            try:
                page.screenshot(path="wake_attempt_screenshot.png")
                print("Saved diagnostic screenshot to wake_attempt_screenshot.png")
            except Exception as screenshot_error:
                print(f"Failed to capture screenshot: {screenshot_error}")
            sys.exit(1)
        finally:
            browser.close()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET_URL
    wake_dashboard(url)
