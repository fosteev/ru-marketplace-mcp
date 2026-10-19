"""__internal API tier for Wildberries (added 2026-10-17).

WB moved catalog data behind its wbaas WAF in Oct 2026: card.wb.ru and
search.wb.ru answer 403 to every non-browser client regardless of headers,
cookies or TLS fingerprint (curl_cffi chrome impersonation included). The SPA
itself switched to same-origin ``www.wildberries.ru/__internal/...`` endpoints
which check:

* cookies ``x_wbaas_token`` + ``_wbauid`` — issued by the antibot JS challenge
  (the 🐴 interstitial; a plain headless Chromium is detected via
  ``navigator.webdriver`` + the ``HeadlessChrome`` UA token and never passes,
  masking both makes the challenge solve);
* SPA headers: ``deviceid``, ``x-queryid``, ``x-requested-with``,
  ``x-spa-version``, ``x-userid``.

Replayed over plain HTTP (httpx) those pass, so this tier keeps a small cookie
jar on disk and refreshes it through a masked headless Chrome when it goes
stale.

Endpoints (verified live 2026-10-17):
* ``/__internal/u-search/exactmatch/ru/common/v18/search`` -> ``{products[100], total}``
* ``/__internal/u-card/cards/v4/detail?nm=<one id>`` -> ``{products[]}``
  (batching ids with ``;`` is rejected with the 498 challenge page — fetch one
  id at a time).

Product objects are the same v4 shape the legacy card.wb.ru returned, so the
existing ``_card_item_dict`` mapping works unchanged.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

import httpx
from mcp_core.logging import log_event

BASE = "https://www.wildberries.ru"
SEARCH_PATH = "/__internal/u-search/exactmatch/ru/common/v18/search"
CARD_PATH = "/__internal/u-card/cards/v4/detail"

# dest the SPA uses for Moscow (positive form; the legacy negative id also
# works — verified — but match the SPA to stay on the beaten path).
DEST_SPA = "1259570991"

STATE_PATH = Path(
    os.environ.get(
        "WB_INTERNAL_STATE",
        str(Path.home() / ".marketplace-mcp" / "wb_internal_state.json"),
    )
)

_LOCK = asyncio.Lock()
_state: dict[str, Any] | None = None


class WbInternalStale(Exception):
    """Cookies are missing/expired — the caller should refresh and retry."""


def _load_state() -> dict[str, Any]:
    global _state
    if _state is None:
        try:
            _state = json.loads(STATE_PATH.read_text())
        except Exception:
            _state = {}
        if "deviceid" not in _state:
            _state["deviceid"] = "site_" + uuid.uuid4().hex
    return _state


def _save_state() -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(_load_state(), ensure_ascii=False, indent=1))
    try:
        STATE_PATH.chmod(0o600)  # cookies are credentials
    except Exception:
        pass


def _cookie_header(state: dict[str, Any]) -> str:
    return "; ".join(
        f"{k}={v}" for k, v in state.get("cookies", {}).items() if v
    )


def _headers(referer: str) -> dict[str, str]:
    state = _load_state()
    return {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ru-RU,ru;q=0.9",
        "Referer": referer,
        "Origin": "https://www.wildberries.ru",
        "deviceid": state["deviceid"],
        "x-queryid": f"qid{int(time.time() * 1000)}{uuid.uuid4().int % 1000000}",
        "x-requested-with": "XMLHttpRequest",
        "x-spa-version": "14.28.4",
        "x-userid": "0",
        "Cookie": _cookie_header(state),
    }


async def _get_json(path: str, params: dict[str, str], referer: str) -> dict[str, Any]:
    """One GET; raises WbInternalStale on 403/498, ValueError on bad JSON."""
    url = f"{BASE}{path}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0)) as client:
        r = await client.get(url, params=params, headers=_headers(referer))
    if r.status_code in (403, 498):
        raise WbInternalStale(f"HTTP {r.status_code}")
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, dict):
        raise ValueError("non-object response")
    return data


async def u_search(query: str, page: int = 1, dest: str = DEST_SPA) -> tuple[list[dict], int | None]:
    """Text search via the SPA endpoint. Returns (products, total)."""
    params = {
        "appType": "1",
        "curr": "rub",
        "dest": dest,
        "query": query,
        "resultset": "catalog",
        "sort": "popular",
        "spp": "30",
        "lang": "ru",
        "locale": "ru",
        "page": str(page),
    }
    referer = f"{BASE}/catalog/0/search.aspx?search={urllib.parse.quote(query)}"
    data = await _get_json(SEARCH_PATH, params, referer)
    products = data.get("products")
    if not isinstance(products, list):
        raise ValueError("no products array")
    total = data.get("total")
    return [p for p in products if isinstance(p, dict)], total if isinstance(total, int) else None


async def u_card(nm_ids: list[int], dest: str = DEST_SPA) -> list[dict]:
    """Card details, one nm per request (`;`-batches get the 498 page)."""
    out: list[dict] = []
    for nm in nm_ids:
        params = {
            "appType": "1",
            "curr": "rub",
            "dest": dest,
            "spp": "30",
            "hide_vflags": "4294967296",
            "mtype": "257",
            "lang": "ru",
            "ab_testing": "false",
            "nm": str(nm),
        }
        data = await _get_json(CARD_PATH, params, f"{BASE}/catalog/{nm}/detail.aspx")
        for p in data.get("products") or []:
            if isinstance(p, dict):
                out.append(p)
        await asyncio.sleep(0.3)  # be polite to the same-origin gateway
    return out


async def refresh_cookies() -> bool:
    """Pass the wbaas challenge in a masked headless Chrome; save cookies.

    Masking: UA without the ``HeadlessChrome`` token +
    ``navigator.webdriver -> false`` injected before any site script. Both are
    required — with either one present the challenge loops forever (verified
    2026-10-17). Uses the system Chrome via channel="chrome" (playwright's
    bundled chromium is not installed in this venv).
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            channel="chrome",
            headless=os.environ.get("WB_HEADLESS", "1") != "0",
        )
        try:
            ctx = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
                ),
                locale="ru-RU",
            )
            await ctx.add_init_script(
                'Object.defineProperty(Navigator.prototype, "webdriver", '
                "{get: () => false, configurable: true});"
            )
            page = await ctx.new_page()
            for attempt in range(2):
                try:
                    await page.goto(BASE + "/", wait_until="domcontentloaded")
                    break
                except Exception as exc:  # transient net::ERR_* on the tunnel
                    if attempt == 1:
                        raise
                    log_event("wb_internal.refresh_retry", error=str(exc)[:150])
                    await page.wait_for_timeout(3000)
            deadline = time.monotonic() + 60
            ok = False
            while time.monotonic() < deadline:
                title = await page.title()
                cookies = {c["name"]: c["value"] for c in await ctx.cookies(BASE + "/")}
                if "x_wbaas_token" in cookies and "🐴" not in title and len(title) > 3:
                    ok = True
                    break
                await page.wait_for_timeout(3000)
            if not ok:
                # last chance: cookies with the site title still showing the
                # horse prefix are fine — the SPA does not always clean it.
                cookies = {c["name"]: c["value"] for c in await ctx.cookies(BASE + "/")}
                ok = "x_wbaas_token" in cookies and len(cookies.get("x_wbaas_token", "")) > 50
            if ok:
                state = _load_state()
                state["cookies"] = cookies
                state["refreshed_at"] = time.time()
                _save_state()
            return ok
        finally:
            await browser.close()


async def _with_refresh(fn, *args, **kwargs):
    """Run fn; on stale cookies refresh once and retry once."""
    try:
        return await fn(*args, **kwargs)
    except WbInternalStale:
        async with _LOCK:
            ok = await refresh_cookies()
        if not ok:
            raise
        return await fn(*args, **kwargs)


async def search(query: str, page: int = 1, dest: str = DEST_SPA):
    return await _with_refresh(u_search, query, page, dest)


async def card(nm_ids: list[int], dest: str = DEST_SPA):
    return await _with_refresh(u_card, nm_ids, dest)
