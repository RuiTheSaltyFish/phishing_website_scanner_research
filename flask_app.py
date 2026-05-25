import csv
import io
import os
import logging
import traceback
from typing import Literal, Union
from urllib.parse import parse_qs, unquote, urlparse

from datetime import datetime

from flask import Flask, Response, render_template, jsonify, request, session
import pandas as pd
import requests
import tldextract
import urllib3
import requests
from fake_useragent import UserAgent
from tldextract import extract
from detectionattrenum import DetectMode
from playwright.sync_api import sync_playwright

from rule_parser.dom_rule import DomRule
from rule_parser.domain_rule import DomainRule
from rule_parser.url_rule import UrlRule
import rule_parser.yaml_rule_parser as p
from url_detection import UrlDetectionHandler, UrlDetectionResult
from dom_object_detection import DomObjectDetectionHandler, DomDetectionResult

from domain_detection import DomainDetectionHandler, DomainDetectionResult


csv_cache = {}
app = Flask(__name__)
app.secret_key = os.urandom(24)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


_domain_dh = None
_url_dh = None
_dom_dh = None


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "rb.gy",
    "qrco.de", "q-r.to", "l.ead.me", "snip.ly",
    "qr-codes.io", "zpr.io", "did.li",
    "ct.ws", "orbitor.dev", "wl.co", "t.co", "mub.me",
    "ow.ly", "buff.ly", "dlvr.it", "short.io",
    "shorte.st", "adf.ly", "bc.vc", "sh.st",
    "cur.lv", "clk.sh", "lnkd.in", "go.ly",
    "tiny.cc", "shorturl.at", "cutt.ly", "rebrand.ly",
    "soo.gd", "qr.ae", "v.gd", "u.to",
    "git.io", "youtu.be", "goo.gl", "ift.tt",
    "wp.me", "tr.im", "x.co", "ff.im",
    "su.pr", "ht.ly", "ping.fm", "post.ly",
    "surl.li", "chk.me", "i.gal", "hm.ru",
    "uniqo.de", "ln.run", "gtly.to", "kutt.it",
    "s.id", "urlis.net", "t2m.io", "shrtco.de",
    "chilp.it", "clicky.me", "vzturl.com", "qr1.be",
    "1url.com", "hyperurl.co", "smarturl.it", "spoti.fi"
}

SEARCH_ENGINES = {
    "google.com", "google.com.hk", "google.co.jp", "google.co.uk",
    "google.com.my", "google.com.sg", "google.com.au",
    "bing.com", "yahoo.com", "baidu.com", "yandex.com",
    "duckduckgo.com",
}

DOMAIN_PARKING = {
    "website.org", "expireddomains.com", "sedoparking.com",
    "dan.com", "hugedomains.com", "godaddy.com", "namecheap.com",
    "afternic.com", "sedo.com", "parking.com", "uniregistry.com",
    "above.com", "bodis.com", "parkingcrew.net", "domainnameshop.com",
    "undeveloped.com", "squadhelp.com", "flippa.com", "brandpa.com",
    "brandbucket.com", "novanym.com", "subdomain.com", "buydomains.com",
    "domainmarket.com", "epik.com", "registrar.eu", "domainagent.com",
}

SKIPPING_CASE = [
    "phishing", "404", "503", "just a moment", "attention required",
    "sitenotfound", "blognotfound", "deployment unavailable",
    "403", "blocked", "access denied", "captcha", "please verify",
    "unusual traffic", "checking your browser...",
    "vérification de sécurité", "honninkakunin", "zugriff verweigert",
    "hosting services unavailable", "site currently unavailable",
    "this store is unavailable", "website expired", "coming soon",
    "unknown domain", "redirecting...",
    "error: the request could not be satisfied",
    "opensearch dashboards",
]

SKIPPING_CASE = [s.lower().strip().replace(" ", "").replace("\t", "") for s in SKIPPING_CASE]


def init_detection_handler():
    global _domain_dh, _url_dh, _dom_dh
    par = p.YamlToRuleParser("rules")
    url_rule_list, dom_rule_list, domain_rule_list = par.yaml_to_rule()
    _domain_dh = DomainDetectionHandler(domain_rules=domain_rule_list)
    _url_dh = UrlDetectionHandler(url_rules=url_rule_list)
    _dom_dh = DomObjectDetectionHandler(dom_rules=dom_rule_list)


def search_engine_redirect_detect(url: str) -> str | None:
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    search_engines = {
        "google", "bing", "yahoo", "baidu", "duckduckgo", "yandex", "ecosia", "brave"
    }
    redirect_param = ["q", "u", "url", "uddg", "RU", "continue", "next"]
    if ext.domain not in search_engines:
        return None
    params = parse_qs(parsed.query)
    for param in redirect_param:
        if param in params:
            value = unquote(params[param][0])
            if value.startswith(("http://", "https://")):
                return value
    return None


def fetch_html(web_url: str) -> tuple[str, int, str]:
    if not web_url or not web_url.startswith(("http://", "https://")):
        raise Exception(f"Invalid URL scheme: {web_url}")

    try:
        with sync_playwright() as p:
            redirect_counter = 0
            final_url = ""
            browser = None
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-features=SafeBrowsing",
                        "--safebrowsing-disable-auto-update",
                        "--disable-logging",
                        "--log-level=3",
                    ]
                )
                ua = UserAgent(browsers=['Chrome'])
                context = browser.new_context(
                    ignore_https_errors=True,
                    user_agent=ua.chrome,
                    viewport={"width": 1920, "height": 1080},
                    locale="en-US",
                    timezone_id="America/New_York",
                    extra_http_headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                        "Sec-CH-UA-Mobile": "?0",
                        "Sec-CH-UA-Platform": '"Windows"',
                        "Sec-Fetch-Dest": "document",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-User": "?1",
                        "Cache-Control": "max-age=0",
                    }
                )

                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                        configurable: true,
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5],
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                    });
                    window.chrome = {
                        runtime: {},
                    };
                """)

                page = context.new_page()

                def get_root_domain(url: str) -> str:
                    extracted = extract(url)
                    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

                def domain_in_set(url: str, domain_set: set) -> bool:
                    root = get_root_domain(url)
                    return root in domain_set

                def same_root_domain(url1: str, url2: str) -> bool:
                    d1 = extract(url1)
                    d2 = extract(url2)
                    return d1.domain == d2.domain and d1.suffix == d2.suffix

                def handle_frame_navigated(frame, url):
                    nonlocal redirect_counter
                    nonlocal final_url
                    if frame == page.main_frame:
                        if not same_root_domain(url, frame.url):
                            redirect_counter += 1
                            final_url = frame.url

                is_search_engine_redirect = search_engine_redirect_detect(web_url)
                if is_search_engine_redirect is not None:
                    web_url = is_search_engine_redirect

                page.on("framenavigated", lambda frame: handle_frame_navigated(frame, web_url))

                page.goto(web_url, wait_until="load", timeout=30000)
                try:
                    page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass

                title = page.title().lower().replace(" ", "")
                if any(skip in title for skip in SKIPPING_CASE):
                    try:
                        page.wait_for_timeout(timeout=20000)
                    except Exception:
                        pass
                    title = page.title().lower().replace(" ", "")
                    if any(skip in title for skip in SKIPPING_CASE):
                        raise Exception(f"Skipping: {title}")

                if final_url:
                    if domain_in_set(final_url, DOMAIN_PARKING):
                        raise Exception(f"Landed on redirect sink domain: {final_url}")
                    if domain_in_set(final_url, SEARCH_ENGINES):
                        raise Exception(f"Landed on search engine domain: {final_url}")

                content = page.content()
                return content, redirect_counter, final_url

            finally:
                try:
                    if browser:
                        browser.close()
                except Exception:
                    pass

    except Exception as e:
        raise Exception(f"fetch_html failed [{web_url}]: {e}")


def process_url(url):

    def rule_to_dict(rule: Union[UrlRule, DomRule, DomainRule], source: str) -> dict:
        severity = "low"
        if rule.risk_score >= 4:
            severity = "high"
        elif rule.risk_score >= 2 :
            severity = "medium"
  

        return {
            "name":        str(rule.title),
            "source":      source,
            "severity":    severity,
            "risk_score":  int(rule.risk_score),
            "description": str(rule.description),
        }

    try:
        html, redirect_counter, final_url = fetch_html(url)

        domain_result: DomainDetectionResult = _domain_dh.run_detection(url, redirect_counter, final_url)
        url_result: UrlDetectionResult = _url_dh.run_detection(url, final_url)

        if final_url != "":
            dom_result: DomDetectionResult = _dom_dh.run_detection(final_url, html)
        else:
            dom_result: DomDetectionResult = _dom_dh.run_detection(url, html)

        risk_score = (
            dom_result.risk_score
            + url_result.risk_score
            + domain_result.risk_score
        )

        return url, {
            "matched_rules": (
                [rule_to_dict(r, "url")    for r in url_result.flagged_rules]
                + [rule_to_dict(r, "domain") for r in domain_result.flagged_rules]
                + [rule_to_dict(r, "dom")    for r in dom_result.flagged_rules]
            ),
            "risk_score": risk_score,
        }

    except Exception as e:
        traceback.print_exc()
        return url, {"error": str(e)}


def _score_result_context(url, result):
    """Shared helper — build template context from a processed result dict."""
    risk_score    = result["risk_score"]
    matched_rules = result["matched_rules"]

    if risk_score >= 4:
        risk_level, risk_label = "high",   "Almost certain is a Phishing Website"
    elif risk_score >= 3:
        risk_level, risk_label = "medium",   "Suspicious but not certain"
    elif risk_score >= 2:
        risk_level, risk_label = "medium", "Likely suspicious, proceed with caution"
    else:
        risk_level, risk_label = "low",    "Likely not a phishing website"

    return dict(
        url=url,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_label=risk_label,
        matched_rules=matched_rules,
    )


def _is_htmx(req) -> bool:
    """Return True when the request was made by HTMX."""
    return req.headers.get("HX-Request") == "true"


@app.get("/")
def home():
    return render_template("main.html")


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    url = request.form.get('url')
    _, result = process_url(url)

    if "error" in result:
        # Minimal error response — enhance as needed
        error_html = f"""
        <main id="main-content" style="flex:1;display:flex;align-items:center;
              justify-content:center;padding:4rem 2rem;text-align:center">
          <div>
            <p style="color:var(--error);font-family:'Manrope',sans-serif;
                      font-weight:800;font-size:1.4rem;margin-bottom:0.75rem">
              Scan Failed
            </p>
            <p style="color:var(--muted);font-size:0.9rem;max-width:32rem">
              {result['error']}
            </p>
            <a href="/" style="display:inline-block;margin-top:1.5rem;
                               color:var(--primary);font-size:0.9rem">
              ← Try another URL
            </a>
          </div>
        </main>"""

        if _is_htmx(request):
            return error_html, 200

        # Full-page fallback (direct navigation)
        return render_template("main.html"), 200

    ctx = _score_result_context(url, result)

  
    return render_template("result.html", **ctx)

  


if __name__ == "__main__":
    init_detection_handler()
    app.run(debug=True)