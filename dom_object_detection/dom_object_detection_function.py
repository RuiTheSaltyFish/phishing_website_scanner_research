import hashlib
import logging
import re
import time
from urllib.parse import parse_qs, unquote, urlparse
from bs4 import BeautifulSoup
from camoufox import Camoufox
from fake_useragent import UserAgent
import tldextract
import html as html_lib
from rapidfuzz import fuzz
from playwright.sync_api import sync_playwright
from rule_parser import DomRule
from pypinyin import lazy_pinyin, Style
from transliterate import translit
import cutlet
import pykakasi
import re

TAG_ATTR_MAP = {
    "script": ["src"],
    "link":   ["href"],
    "img":    ["src"],
    "iframe": ["src"],
    "a":      ["href"],
    "form":   ["action"],
    'meta':   ['content', 'href']
}

SKIPPING_CASE = [
    "phishing",
    "404",
    "503",
    "验证页面",
    "just a moment",
    "attention required",
    "sitenotfound",
    "blognotfound",
    "deployment unavailable",
    "plesk",
    "403",
    "blocked",
    "access denied",
    "captcha",
    "please verify",
    "unusual traffic",
    "deployment unavailable",
    "checking your browser...",
    "vérification de sécurité",
    "honninkakunin",
    "zugriff verweigert",
    "hosting services unavailable",
    "site currently unavailable",
    "this store is unavailable",
    "website expired",
    "coming soon",
    "unknown domain",
    "redirecting...",
    "error: the request could not be satisfied",
    "opensearch dashboards",
]

SKIPPING_CASE = [s.lower().strip().replace(" ", "").replace("\t", "") for s in SKIPPING_CASE]

HOSTING_PLATFORM= [
        "linktr.ee",
        "bio.site",
        "beacons.ai",
        "taplink.cc",
        "linktree.com",
        "forms.app",
        "my.forms.app",
        "forms.visme.co",
        "typeform.com",
        "jotform.com",
        "surveymonkey.com",
        "portfolio.adobe.com",
        "carrd.co",
        "wix.com",
        "squarespace.com",
        "strikingly.com",
        "weebly.com",
        "notion.site",
        "get.teamviewer.com",
        "ipinfo.io",
        "fruits.co"
    ]



def remove_url_path(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    bare_domain = netloc.removeprefix("www.")

    # 检测 path / 后面有没有字符
    path = parsed.path.strip('/')
    if not path:
        return url  # 没有 path 直接返回原本 URL

    # Check if bare domain matches any hosting platform entry
    is_hosting = any(
        bare_domain == platform or bare_domain.endswith("." + platform)
        for platform in HOSTING_PLATFORM
    )

    if is_hosting:
        return url
    else:
        return f"{parsed.scheme}://{parsed.netloc}"



def suspicious_use_of_high_risk_tag(soup: BeautifulSoup,checkcase: list[str] = [], trusted_src: list[str] = []) -> bool:
    try:
        for tag_name in ("iframe", "embed", "object"):
            for tag in soup.find_all(tag_name):
                src    = tag.get("src") or tag.get("data") or ""
                style  = tag.get("style", "").replace(" ", "")

                if not checkcase:
                    return True

                if "hidden" in checkcase:
                        is_hidden = (
                            "display:none" in style or
                            "visibility:hidden" in style
                        )
                        
                if is_hidden:
                    ext = tldextract.extract(src)
                    domain = f"{ext.domain}.{ext.suffix}"
                    if domain not in trusted_src:
                        return True

                if "data" in checkcase:
                    if src.startswith("data:"):
                        return True

                if "javascript" in checkcase:
                    if src.startswith("javascript:"):
                        return True
                
                
        return False
    except Exception as e:
        logging.error(f"suspicious_use_of_high_risk_tag : {e}")
        return False



def body_tag_count(soup: BeautifulSoup, min_text_length=4200, min_tag_count=258):
    """
    Check if a BeautifulSoup object has sparse content.
    
    Args:
        soup: BeautifulSoup object
        min_text_length: Minimum required text length (default: 100)
        min_tag_count: Minimum required tag count (default: 10)
    
    Returns:
        True if content is below thresholds, False otherwise
    """
    body = soup.find('body') or soup
    
    text_length = len(body.get_text(strip=True))
    tag_count = len(body.find_all())
    
    return text_length < min_text_length or tag_count < min_tag_count


def count_high_risk_tag(soup: BeautifulSoup, forbidden_tag: list) -> int:
    try:
        return sum(len(soup.find_all(tag)) for tag in forbidden_tag)
    except Exception as e:
        logging.error(f"check_high_risk_tag : {e}")
        return 0

def check_mailto_form(soup: BeautifulSoup,rule:DomRule):

    try:
        
        form_tags = soup.find_all("form")
        
        for ft in form_tags:
            action = ft.get("action")
            if action:
                if action.startswith("mailto"):
                    return True
                
        return False

    except Exception as e:
        logging.error(f"check_form_action:{e}")
        raise

def count_detected_technologies(soup,tech_list:dict,min_appear):
    """
    Count detected technologies: Google Analytics, jQuery, Bootstrap, Cloudflare.
    Returns count (0-4). Low count = phishing indicator.
    """

    technologies = set()

    all_scripts = soup.find_all("script", src=True)
    all_src = " ".join(s.get("src", "").lower() for s in all_scripts)

    inline_scripts = soup.find_all("script", src=False)
    inline_text = " ".join(s.string for s in inline_scripts if s.string).lower()

    all_links = soup.find_all("link", rel=True)
    all_href = " ".join(l.get("href", "").lower() for l in all_links)

    combined_text = all_src + " " + inline_text + " " + all_href

    for tech_name, tech_info in tech_list.items():
        patterns = tech_info.get("patterns", [])
        if any(p.lower() in combined_text for p in patterns):
            technologies.add(tech_name)

    return  len(technologies) < min_appear



def count_fuzzy_title_domain_ratio(soup: BeautifulSoup, web_url: str):
    try:
        title_tag = soup.find("title")
        title_str = title_tag.text.strip() if title_tag else None

        if title_str is None:
            return 0.0
        
        ext = tldextract.extract(web_url)
        domain_main_lower = ext.domain.lower()
        sub_domain_lower = ext.subdomain.lower()
        title_normalized = _normalize(title_str)
        sub_domain_ratio = 0.0
        
        domain_ratio = fuzz.partial_ratio(domain_main_lower, title_normalized)
        domain_ratio = domain_ratio / 100
        
        if sub_domain_lower:
            sub_domain_ratio = fuzz.partial_ratio(sub_domain_lower, title_normalized)
            sub_domain_ratio = sub_domain_ratio / 100
            return min(sub_domain_ratio,domain_ratio)
        
        return domain_ratio
    
        
    
    except Exception as e:
        logging.error(f"cross_domain_form_action:{e}")
        raise


def cross_domain_form_action(soup: BeautifulSoup, web_url: str, check_method: list, trusted_src: list = []) -> bool:
    try:
        page_ext = tldextract.extract(web_url)
        page_root = f"{page_ext.domain}.{page_ext.suffix}"

        check_method_upper = [m.upper() for m in check_method]
        trusted_src_lower = [d.lower() for d in trusted_src]

        for form in soup.find_all("form"):
            method = form.get("method", "").strip().upper()
            if check_method_upper and method not in check_method_upper:
                continue

            action = form.get("action", "").strip()
            if not action:
                continue
            if action.startswith("/") or action.startswith("."):
                continue
            if action.startswith("#") or action.lower().startswith("javascript:"):
                continue

            # 处理 protocol-relative URL
            if action.startswith("//"):
                action = "https:" + action

            action_ext = tldextract.extract(action)
            if action_ext.domain == "www":
            # www.gov.uk 这类情况，domain 实际上是 suffix
                action_root = action_ext.suffix
            else:
                action_root = f"{action_ext.domain}.{action_ext.suffix}"
            
            # 解析失败或空域名
            if not action_ext.domain or not action_ext.suffix:
                continue

            if action_root.lower() in trusted_src_lower:
                continue

            if action_root != page_root:
                return True
        
        return False
    except Exception as e:
        logging.error(f"cross_domain_form_action:{e}")
        raise
    

def cross_domain_js(soup: BeautifulSoup, web_url: str, trusted_src: list = []) -> bool:
    try:
        page_ext  = tldextract.extract(web_url)
        page_root = f"{page_ext.domain}.{page_ext.suffix}".lower()
        trusted_src_lower = [d.lower() for d in trusted_src]

        submit_patterns = [
            re.compile(r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"]([^\'"]+)[\'"]', re.DOTALL),
            re.compile(r'\.post\s*\(\s*[\'"]([^\'"]+)[\'"]'),
            re.compile(r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]'),
            re.compile(r'\.open\s*\(\s*[\'"]POST[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]'),
            re.compile(r'sendBeacon\s*\(\s*[\'"]([^\'"]+)[\'"]'),
            re.compile(r'(?:new\s+Image\s*\(\s*\)|Image\s*\(\s*\))\.src\s*=\s*[\'"]([^\'"]+)[\'"]'),
            re.compile(r'\.action\s*=\s*[\'"]([^\'"]+)[\'"]'),
        ]

        for script in soup.find_all("script"):
            text = script.string or ""
            for pattern in submit_patterns:
                for match in pattern.findall(text):
                    # 处理 protocol-relative URL
                    if match.startswith("//"):
                        match = "https:" + match
                    elif not match.startswith("http"):
                        continue

                    ext    = tldextract.extract(match)
                    if ext.domain == "www":
                    # www.gov.uk 这类情况，domain 实际上是 suffix
                        domain = ext.suffix.lower()
                    else:
                        domain = f"{ext.domain}.{ext.suffix}".lower()

                    if not ext.domain or not ext.suffix:
                        continue
                    if domain == page_root:
                        continue
                    if domain in trusted_src_lower:
                        continue

                    return True

        return False
    except Exception as e:
        logging.error(f"cross_domain_js: {e}")
        raise


def get_meta_script_link_external_ratio(soup: BeautifulSoup, web_url: str,base_amount:int, tag=[], trusted_src=[]) -> float:
    try:
        global TAG_ATTR_MAP

        base_ext = tldextract.extract(web_url)
        if base_ext.domain == "www":
            base_domain = base_ext.suffix.lower()
        else:
            base_domain = f"{base_ext.domain}.{base_ext.suffix}".lower()

        trusted_lower = [t.lower() for t in trusted_src]

        total = 0
        external = 0
        TAG_ATTR_MAP = {item: TAG_ATTR_MAP.get(item) for item in tag}

        for tag_name, attrs in TAG_ATTR_MAP.items():
            for element in soup.find_all(tag_name):
                for attr in attrs:
                    url = element.get(attr)
                    if not url or not (url.startswith('http') or url.startswith('https')):
                        continue

                    ext = tldextract.extract(url)
                    if ext.domain == "www":
                        link_domain = ext.suffix.lower()
                    else:
                        link_domain = f"{ext.domain}.{ext.suffix}".lower()

                    # trusted_src 不计入统计
                    if any(t in link_domain for t in trusted_lower):
                        continue

                    total += 1
                    if link_domain != base_domain:
                        external += 1

        if external == 0 or total <= base_amount:
            return 0.0
        
        return external / total

    except Exception as e:
        logging.error(f"get_meta_script_link_external_ratio:{e}")
        raise





def _to_pinyin(text: str) -> str:
    result = []
    for char in text:
        if '\u4e00' <= char <= '\u9fff':
            result.extend(lazy_pinyin(char, style=Style.NORMAL))
        else:
            result.append(char)
    return ''.join(result).lower()


def _to_romaji(text: str) -> str:
    try:
        kks = pykakasi.kakasi()
        result = kks.convert(text)
        return ''.join(item['hepburn'] for item in result).lower()
    except Exception as e:
        logging.warning(f"_to_romaji error: {e}")
        return text.lower()


def _to_korean(text: str) -> str:
    try:
        from korean_romanizer.romanizer import Romanizer
        result = []
        chunk = []
        for char in text:
            if '\uac00' <= char <= '\ud7af':
                chunk.append(char)
            else:
                if chunk:
                    result.append(Romanizer(''.join(chunk)).romanize())
                    chunk = []
                result.append(char)
        if chunk:
            result.append(Romanizer(''.join(chunk)).romanize())
        return ''.join(result).lower()
    except Exception as e:
        logging.warning(f"_to_korean error: {e}")
        return text.lower()


def _to_cyrillic(text):
        try:
            return translit(text, 'ru', reversed=True).lower()
        except Exception:
            return text.lower()


def _normalize(text: str) -> str:
    # 日文优先（混合汉字+假名）
    if any('\u3040' <= c <= '\u30ff' for c in text):
        return _to_romaji(text)
    if any('\u4e00' <= c <= '\u9fff' for c in text):
        return _to_pinyin(text)
    if any('\uac00' <= c <= '\ud7af' for c in text):
        return _to_korean(text)
    if any('\u0400' <= c <= '\u04ff' for c in text):
        return _to_cyrillic(text)
    return text.lower()


def check_page_title_mismatch(
    soup,
    web_url,
    min_domain_len=4,
    generic_titles=None,
    meta_list=[],
    title_acronym_detection=None,
    min_similarity_threshold=0.70,
):
    """
    Returns True  → page title likely does NOT belong to the domain (mismatch detected).
    Returns False → title appears consistent with the domain (no mismatch).

    title_acronym_detection, if provided, is a dict:
        {"min_acronym_length": int, "acronym_min_similarity_score": float}
    """
    title_tag = soup.find("title")
    title_str = title_tag.text.strip() if title_tag else None
    if not title_str:
        return False

    if generic_titles and any(g in title_str.lower() for g in generic_titles):
        return False

    title_str = html_lib.unescape(title_str)
    title_normalized = _normalize(title_str)

    ext = tldextract.extract(web_url)
    if ext.domain == "www":
        domain_lower, subdomain_lower = ext.suffix.lower(), ""
    else:
        domain_lower, subdomain_lower = ext.domain.lower(), ext.subdomain.lower()

    if len(domain_lower) < min_domain_len:
        return False

    parts = [
        p for p in [domain_lower, subdomain_lower]
        if p and len(p) >= min_domain_len and p != "www"
    ]
    if not parts:
        return False

    title_nospace = title_normalized.replace(" ", "")
    if any(p in title_normalized or p in title_nospace for p in parts):
        return False

    if "og:site_name" in meta_list:
        og = soup.find("meta", property="og:site_name")
        if og:
            sn = _normalize(og.get("content", "").lower())
            if any(p in sn or p in sn.replace(" ", "") for p in parts):
                return False
            if sum(fuzz.partial_ratio(p, sn) / 100 for p in parts) / len(parts) >= min_similarity_threshold:
                return False

    if "og:title" in meta_list:
        og = soup.find("meta", property="og:title")
        if og:
            st = _normalize(og.get("content", "").lower())
            if any(p in st or p in st.replace(" ", "") for p in parts):
                return False
            if sum(fuzz.partial_ratio(p, st) / 100 for p in parts) / len(parts) >= min_similarity_threshold:
                return False

    if title_acronym_detection:
        acronym = "".join(
            w[0].lower() for w in title_str.split() if w and w[0].isalnum()
        )
        if len(acronym) >= title_acronym_detection["min_acronym_length"]:
            if (
                sum(fuzz.ratio(p, acronym) / 100 for p in parts) / len(parts)
                >= title_acronym_detection["acronym_min_similarity_score"]
            ):
                return False

    ratios = [
        fuzz.ratio(p, title_normalized) / 100
        if len(title_normalized) <= min_domain_len
        else fuzz.partial_ratio(p, title_normalized) / 100
        for p in parts
    ]
    if sum(ratios) / len(ratios) >= min_similarity_threshold:
        return False

    page_text = _normalize(soup.get_text(separator=" ", strip=True))
    if any(p in page_text for p in parts):
        return False

    return True


def check_external_request_suspicious(
    soup: BeautifulSoup, 
    web_url: str,
    trusted_src: list = []
) -> bool:

    import re
    from collections import Counter
    
    page_ext = tldextract.extract(web_url)
    page_root = f"{page_ext.domain}.{page_ext.suffix}".lower()
    trusted_lower = [t.lower() for t in trusted_src]
    
    external_domains = []
    
    for tag in soup.find_all(['script', 'img', 'link', 'iframe','meta']):
        src = tag.get('src') or tag.get('href') or ""
        if not src.startswith('http'):
            continue
        ext = tldextract.extract(src)
        if ext.domain == "www":
            domain = ext.suffix.lower()

        else:
            domain = f"{ext.domain}.{ext.suffix}".lower()


        if domain and domain != page_root:
            if not any(t in domain for t in trusted_lower):
                external_domains.append(domain)
    
    if not external_domains:
        return False
    
    # 检测：所有外部资源都来自同一个域名（复制粘贴的钓鱼页面特征）
    counter = Counter(external_domains)
    top_domain, top_count = counter.most_common(1)[0]
    ratio = top_count / len(external_domains)
    
    # 80%以上外部资源来自同一域名 = 可疑
    if ratio >= 0.8:
        return True
    
    return False


def check_obfuscated_js(html: str, regex_list: list) -> bool:
    patterns = [re.compile(r) for r in regex_list]
    return any(pattern.search(html) for pattern in patterns)

def check_multiple_submit(soup, config: dict) -> bool:
    min_matches = config["min_matches"]
    scripts     = " ".join(s.get_text() for s in soup.find_all("script"))

    matched = sum(
        1 for p in config["patterns"]
        if re.search(p["regex"], scripts, re.I | re.S)
    )
    return matched >= min_matches



def check_missing_legitimacy_signals(soup, config: dict) -> bool:
    signals   = {s["name"]: s for s in config["signals"]}
    threshold = config["threshold"]
    all_inputs = soup.find_all("input")
    score      = 0

    if "no_nav_and_footer" in signals:
        has_nav    = bool(soup.find(["nav", "header"]))
        has_footer = bool(soup.find("footer"))
        if not has_nav and not has_footer:
            score += signals["no_nav_and_footer"]["weight"]

    if "low_link_density" in signals:
        min_links = signals["low_link_density"]["params"]["min_links"]
        if len(soup.find_all("a", href=True)) < min_links:
            score += signals["low_link_density"]["weight"]

    if "has_password_field" in signals:
        if any(i.get("type") == "password" for i in all_inputs):
            score += signals["has_password_field"]["weight"]

    if "no_images" in signals:
        if not soup.find_all("img"):
            score += signals["no_images"]["weight"]

    if "no_title_or_h1" in signals:
        if not soup.find("title") and not soup.find("h1"):
            score += signals["no_title_or_h1"]["weight"]

    if "no_copyright_text" in signals:
        if not re.search(r'©|copyright|版权', str(soup), re.I):
            score += signals["no_copyright_text"]["weight"]

    if "single_form_single_purpose" in signals:
        max_forms  = signals["single_form_single_purpose"]["params"]["max_forms"]
        max_inputs = signals["single_form_single_purpose"]["params"]["max_inputs"]
        forms = soup.find_all("form")
        visible_inputs = [
            i for i in all_inputs
            if i.get("type") not in ("hidden", "submit", "button", "reset")
        ]
        if len(forms) <= max_forms and len(visible_inputs) <= max_inputs:
            score += signals["single_form_single_purpose"]["weight"]

    if "no_lang_attribute" in signals:
        html_tag = soup.find("html")
        if not html_tag or not html_tag.get("lang"):
            score += signals["no_lang_attribute"]["weight"]

    if "no_favicon" in signals:
        favicon = soup.find("link", rel=lambda r: r and "icon" in r)
        if not favicon:
            score += signals["no_favicon"]["weight"]

    return score >= threshold


def check_double_submit(soup, config: dict) -> bool:
    cfg         = config["double_submit_detection"]
    min_matches = cfg["min_matches"]
    scripts     = " ".join(s.get_text() for s in soup.find_all("script"))

    matched = sum(
        1 for p in cfg["patterns"]
        if re.search(p["regex"], scripts, re.I | re.S)
    )
    return matched >= min_matches


def check_urgency_language(soup) -> bool:
    pattern = r"(账户.{0,10}冻结|立即验证|suspend|verify.{0,10}now|account.{0,10}locked|unusual.{0,10}activity)"
    return bool(re.search(pattern, str(soup), re.I))


def check_beacon_on_leave(soup) -> bool:
    """是否在页面离开时偷发数据"""
    scripts = " ".join(s.get_text() for s in soup.find_all("script"))
    patterns = [
        r"visibilitychange.{0,100}(fetch|sendBeacon|XMLHttpRequest)",
        r"beforeunload.{0,100}(fetch|sendBeacon|XMLHttpRequest)",
        r"pagehide.{0,100}sendBeacon",
    ]
    return any(re.search(p, scripts, re.I | re.S) for p in patterns)

def normalize_element(soup: BeautifulSoup, tag: str, element: str, name: str):
 
    target = soup.find(tag, {element: name})

    if not target:
        return None
    
    dynamic_attrs = [
        'data-bind',
        'value',
        'aria-describedby',
        'placeholder',
        'autocomplete',
    ]

    # 移除动态属性
    for child in target.find_all(True):
        for attr in dynamic_attrs:
            if child.has_attr(attr):
                del child[attr]

    # 外层 + 内层合并
    all_tags = [target] + target.find_all(['input', 'button', 'form', 'div', 'a'])

    structure = []
    for t in all_tags:
        structure.append({
            "tag":   t.name,
            "id":    t.get("id", ""),
            "class": sorted(t.get("class", [])),
            "type":  t.get("type", ""),
            "name":  t.get("name", ""),
            "text":  t.get_text().strip().lower() if t.name != "div" else "",
        })

    normalized = "".join(
        f"{s['tag']}{s['id']}{s['type']}{s['name']}{s['text'].replace(' ', '')}{''.join(s['class']) if s['class'] else ''}"
        for s in structure
    )
    
    return normalized


def hash_element(soup:BeautifulSoup,tag:str,element:str,name:str):
    normalized = normalize_element(soup,tag,element,name)
    if not normalized:
        return None
    return hashlib.md5(normalized.encode()).hexdigest()

def verify_is_mimic_site(web_url: str, soup:BeautifulSoup,hash_list: dict):
    ext = tldextract.extract(web_url)
    domain = f"{ext.domain}.{ext.suffix}".lower()
    for brand, profile in hash_list.items():
        page_hash = hash_element(
            soup,
            profile['tag'],
            profile['element'],
            profile['name']
        )
        
        if not page_hash:
            continue 
        
        if page_hash == profile['hash']:
            return domain != profile["domain"]
        
    return False



def is_login_structure_mimic(soup: BeautifulSoup, web_url: str, structure_list: dict, deficient: float = 80.0):
    ext = tldextract.extract(web_url)
    domain = f"{ext.domain}.{ext.suffix}".lower()

    for brand, profile in structure_list.items():
        current_structure = normalize_element(
            soup,
            profile['tag'],
            profile['element'],
            profile['name']
        )

        if not current_structure:
            continue

        similarity = fuzz.partial_ratio(current_structure, profile['structure'])

        if similarity >= deficient:
            return domain != profile["domain"]

    return False


def phishing_extract_external_links(
    url: str,
    html: str,
    tags: list[str],
    phishing_keywords: list[str],
) -> list[str] | None:

    soup = BeautifulSoup(html, "html.parser")
    page_text = soup.get_text().lower()

    # Step 1: Check phishing keywords
    has_phishing_keyword = any(kw in page_text for kw in phishing_keywords)
    if not has_phishing_keyword:
        return None

    # Step 2: Get current domain
    current = tldextract.extract(url)
    current_domain = f"{current.domain}.{current.suffix}"

    # Step 3: Extract external links from given tags
    external_links = []
    for tag in tags:
        attrs = TAG_ATTR_MAP.get(tag, [])
        for element in soup.find_all(tag):
            for attr in attrs:
                value = element.get(attr, "")
                if not value or not value.startswith(("http://", "https://")):
                    continue
                link = tldextract.extract(value)
                link_domain = f"{link.domain}.{link.suffix}"
                if link_domain != current_domain:
                    external_links.append(value)

    return list(set(external_links))




def __search_engine_redirect_detect(url: str) -> str | None:

    parsed = urlparse(url)
    ext = tldextract.extract(url)
 
    # Only process known search engine domains
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


def phishing_redirect_scam(
    url: str,
    soup: BeautifulSoup,
    tags: list[str],
    phishing_keywords: list[str],
    max_words: int = 500,
) -> bool:

    TAG_ATTR_MAP = {
        "script": ["src"],
        "link":   ["href"],
        "img":    ["src"],
        "iframe": ["src"],
        "a":      ["href"],
        "form":   ["action"],
        "meta":   ["content", "href"],
    }

    page_text = soup.get_text().lower()

    # Step 1: Check word count
    if len(page_text.split()) > max_words:
        return False

    # Step 2: Check phishing keywords
    if phishing_keywords:
        has_phishing_keyword = any(kw in page_text for kw in phishing_keywords)
        if not has_phishing_keyword:
            return False

    # Step 3: Get current domain
    current = tldextract.extract(url)
    current_domain = f"{current.domain}.{current.suffix}"

    # Step 4: Return True on first external link found
    for tag in tags:
        attrs = TAG_ATTR_MAP.get(tag, [])
        for element in soup.find_all(tag):
            for attr in attrs:
                value = element.get(attr, "")
                if not value or not value.startswith(("http://", "https://")):
                    continue
                link = tldextract.extract(value)
                link_domain = f"{link.domain}.{link.suffix}"
                search_engine_redirect =  __search_engine_redirect_detect(value)
                if link_domain != current_domain:
                    return True
                if search_engine_redirect and search_engine_redirect != current_domain:
                    return True

    return False