from urllib.parse import urlparse
import re
import logging
from pypinyin import pinyin_dict
from pypinyin.contrib.tone_convert import to_normal
import requests
from rule_parser import UrlRule
import tldextract
from rapidfuzz import process, fuzz
import nltk
from nltk.corpus import words

nltk.download('words', quiet=True)




def detect_web_url_length(url_rule: UrlRule, web_url: str) -> bool:
    url = web_url
    length_limit = url_rule.url_length_yparam["limit"]
    
    if url_rule.domain_name_only_yparam:
        ext = tldextract.extract(web_url)
        url = ext.domain
    if url_rule.url_length_yparam is not None:
        url_length = len(url)
        if url_length >= length_limit:
            return True
    return False


def is_https(web_url: str) -> bool:
 
    if not isinstance(web_url, str):
        return False  # Ensure input is a string
    return web_url.lower().startswith("https://")

def detect_web_url_subdomain_level(url_rule: UrlRule, web_url: str) -> bool:
    try:
      
        ext = tldextract.extract(web_url)
        subdomain_levels = len(ext.subdomain.split('.')) if ext.subdomain else 0
        return subdomain_levels >= url_rule.sub_domain_level_yparam

    except Exception as e:
        logging.error(f"detect_web_url_subdomain_level error occurred: {e}")
        return False


def detect_hosting_platform_url(url_rule: UrlRule, web_url: str,hosting_list = []):
    ext = tldextract.extract(web_url)
    domain = f"{ext.domain}.{ext.suffix}"
    if domain in hosting_list:
        return True
    
    return False

def detect_url_regex(url_rule: UrlRule, web_url: str) -> bool:
    try:
        url = web_url
        url_regex = url_rule.url_regex_yparam


        if url_rule.domain_name_only_yparam: 
            parsed = urlparse(web_url)
            url = parsed.netloc
            if url.startswith("www."):
                url = url[4:]

            ext = tldextract.extract(url)
            url = url[:-(len(ext.suffix) + 1)]
        if url_regex is not None:
            reg = re.compile(url_regex['regex'])
            method = url_regex['method']
            if method == 'match':
                if reg.match(str(url)):
                    return True
            if method == 'search':
                if reg.search(str(url)):
                    return True
            if method == 'findall':
                result = reg.findall(url)
                if result:
                    return result
        else:
            return False
    except Exception as e:
        logging.error(f"detect_url_regex error occurred: {e}")
        return False

def _build_pinyin_words() -> set:
    pinyin_set = set()
    for code, py in pinyin_dict.pinyin_dict.items():
        for p in py.split(","):
            clean = to_normal(p)
            if clean and clean.isalpha():
                pinyin_set.add(clean.lower())
    return pinyin_set


def _build_japanese_romaji() -> set:
    return {
        "a", "i", "u", "e", "o",
        "ka", "ki", "ku", "ke", "ko",
        "sa", "shi", "su", "se", "so",
        "ta", "chi", "tsu", "te", "to",
        "na", "ni", "nu", "ne", "no",
        "ha", "hi", "fu", "he", "ho",
        "ma", "mi", "mu", "me", "mo",
        "ya", "yu", "yo",
        "ra", "ri", "ru", "re", "ro",
        "wa", "wo", "n",
        "ga", "gi", "gu", "ge", "go",
        "za", "ji", "zu", "ze", "zo",
        "da", "de", "do",
        "ba", "bi", "bu", "be", "bo",
        "pa", "pi", "pu", "pe", "po",
        "kya", "kyu", "kyo",
        "sha", "shu", "sho",
        "cha", "chu", "cho",
        "nya", "nyu", "nyo",
        "hya", "hyu", "hyo",
        "mya", "myu", "myo",
        "rya", "ryu", "ryo",
        "gya", "gyu", "gyo",
        "ja",  "ju",  "jo",
        "bya", "byu", "byo",
        "pya", "pyu", "pyo",
    }



def is_url_shortener(url: str, final_url: str, shorteners_list: list) -> bool:
    if not final_url:
        return False

    ext = tldextract.extract(url)
    domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"

    ext_final = tldextract.extract(final_url)
    domain_final = f"{ext_final.subdomain}.{ext_final.domain}.{ext_final.suffix}" if ext_final.subdomain else f"{ext_final.domain}.{ext_final.suffix}"

    
    if domain in shorteners_list and domain == domain_final:
        raise Exception(f"Shortening service not redirect to source likely being blocked and remove")

    return domain in shorteners_list
    


def _build_korean_romaji() -> set:
    return {
        "a", "ae", "ya", "yae", "eo", "e", "yeo", "ye",
        "o", "wa", "wae", "oe", "yo", "u", "wo", "we",
        "wi", "yu", "eu", "ui", "i",
        "ga", "gae", "gya", "gyae", "geo", "ge", "gyeo", "gye",
        "go", "gwa", "gwae", "goe", "gyo", "gu", "gwo", "gwe",
        "gwi", "gyu", "geu", "gui", "gi",
        "na", "nae", "nya", "nyae", "neo", "ne", "nyeo", "nye",
        "no", "nwa", "nwae", "noe", "nyo", "nu", "nwo", "nwe",
        "nwi", "nyu", "neu", "nui", "ni",
        "da", "dae", "dya", "dyae", "deo", "de", "dyeo", "dye",
        "do", "dwa", "dwae", "doe", "dyo", "du", "dwo", "dwe",
        "dwi", "dyu", "deu", "dui", "di",
        "ra", "rae", "rya", "ryae", "reo", "re", "ryeo", "rye",
        "ro", "rwa", "rwae", "roe", "ryo", "ru", "rwo", "rwe",
        "rwi", "ryu", "reu", "rui", "ri",
        "ma", "mae", "mya", "myae", "meo", "me", "myeo", "mye",
        "mo", "mwa", "mwae", "moe", "myo", "mu", "mwo", "mwe",
        "mwi", "myu", "meu", "mui", "mi",
        "ba", "bae", "bya", "byae", "beo", "be", "byeo", "bye",
        "bo", "bwa", "bwae", "boe", "byo", "bu", "bwo", "bwe",
        "bwi", "byu", "beu", "bui", "bi",
        "sa", "sae", "sya", "syae", "seo", "se", "syeo", "sye",
        "so", "swa", "swae", "soe", "syo", "su", "swo", "swe",
        "swi", "syu", "seu", "sui", "si",
        "ja", "jae", "jya", "jyae", "jeo", "je", "jyeo", "jye",
        "jo", "jwa", "jwae", "joe", "jyo", "ju", "jwo", "jwe",
        "jwi", "jyu", "jeu", "jui", "ji",
        "cha", "chae", "chya", "chyae", "cheo", "che", "chyeo", "chye",
        "cho", "chwa", "chwae", "choe", "chyo", "chu", "chwo", "chwe",
        "chwi", "chyu", "cheu", "chui", "chi",
        "ka", "kae", "kya", "kyae", "keo", "ke", "kyeo", "kye",
        "ko", "kwa", "kwae", "koe", "kyo", "ku", "kwo", "kwe",
        "kwi", "kyu", "keu", "kui", "ki",
        "ta", "tae", "tya", "tyae", "teo", "te", "tyeo", "tye",
        "to", "twa", "twae", "toe", "tyo", "tu", "two", "twe",
        "twi", "tyu", "teu", "tui", "ti",
        "pa", "pae", "pya", "pyae", "peo", "pe", "pyeo", "pye",
        "po", "pwa", "pwae", "poe", "pyo", "pu", "pwo", "pwe",
        "pwi", "pyu", "peu", "pui", "pi",
        "ha", "hae", "hya", "hyae", "heo", "he", "hyeo", "hye",
        "ho", "hwa", "hwae", "hoe", "hyo", "hu", "hwo", "hwe",
        "hwi", "hyu", "heu", "hui", "hi",
        "kka", "kkae", "kkeo", "kke", "kko", "kku", "kki",
        "tta", "ttae", "tteo", "tte", "tto", "ttu", "tti",
        "ppa", "ppae", "ppeo", "ppe", "ppo", "ppu", "ppi",
        "ssa", "ssae", "sseo", "sse", "sso", "ssu", "ssi",
        "jja", "jjae", "jjeo", "jje", "jjo", "jju", "jji",
    }


ENGLISH_WORDS = set(w.lower() for w in words.words() if 3 <= len(w) <= 15)
PINYIN_WORDS    = _build_pinyin_words()
JAPANESE_ROMAJI = _build_japanese_romaji()
KOREAN_ROMAJI   = _build_korean_romaji()
COMBINED_WORDS  = ENGLISH_WORDS | PINYIN_WORDS | JAPANESE_ROMAJI | KOREAN_ROMAJI

def calculate_domain_name_entrophy(web_url: str, min_length: int = 4, threshold: float = 80.0) -> bool:

    def dp_match(word: str, dictionary: set) -> bool:
        w = word.lower()
        n = len(w)
        dp = [False] * (n + 1)
        dp[0] = True
        for i in range(1, n + 1):
            for j in range(max(0, i - 15), i):
                if dp[j]:
                    chunk = w[j:i]
                    if len(chunk) >= 2 and chunk in dictionary:
                        dp[i] = True
                        break
        return dp[n]

    def score(word: str) -> bool:
        if not word:
            return True

        # 去掉数字后再匹配
        w_alpha = re.sub(r"\d+", "", word.lower())
        if not w_alpha or len(w_alpha) < min_length:
            return True

        # 1. 英文单库 DP
        if dp_match(w_alpha, ENGLISH_WORDS):
            return True

        # 2. 英文 fuzzy fallback
        match = process.extractOne(
            w_alpha, list(ENGLISH_WORDS),
            scorer=fuzz.ratio,
            score_cutoff=threshold
        )
        
        if match:
            return True

        # 3. 中文拼音单库 DP
        if dp_match(w_alpha, PINYIN_WORDS):
            return True

        # 4. 日文罗马音单库 DP
        if dp_match(w_alpha, JAPANESE_ROMAJI):
            return True

        # 5. 韩文罗马音单库 DP
        if dp_match(w_alpha, KOREAN_ROMAJI):
            return True

        # 6. 跨词库混合 DP
        if dp_match(w_alpha, COMBINED_WORDS):
            return True

        return False

    # ── 域名解析 ────────────────────────────────────────────────
    ext = tldextract.extract(web_url)

    if ext.domain == "www":
        domain    = ext.suffix.lower()
        subdomain = ""
    else:
        domain    = ext.domain.lower()
        subdomain = ext.subdomain.lower() if ext.subdomain else ""

    if len(domain) < min_length:
        return False

    if not score(domain):
        return True

    for part in subdomain.split("."):
        if part and part != "www" and len(part) >= min_length:
            if not score(part):
                return True

    return False


def _edit_distance(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i-1] == b[j-1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]

def is_typosquatting(
    web_url: str,
    target_domains: list[str],
    digit_substitution: dict[str, str],
    homoglyph_map: dict[str, str],
) -> bool:

    def normalize(word: str) -> str:
        w = word.lower()
        w = ''.join(digit_substitution.get(c, c) for c in w)
        for glyph, replacement in sorted(homoglyph_map.items(), key=lambda x: len(x[0]), reverse=True):
            w = w.replace(glyph, replacement)
        return w

    def check_part(part: str) -> bool:
        if not part or len(part) <= 3:
            return False
        normalized = normalize(part)
        for known in target_domains:
            known_lower = known.lower()

            # 完全匹配 → 跳过，真实品牌域名不是 typosquatting
            if part.lower() == known_lower:
                continue

            # normalize 后完全匹配 → 是 typosquatting（如 "gooogle" → "google"）
            if normalized == known_lower and part.lower() != known_lower:
                return True

            # edit distance 检测
            if abs(len(normalized) - len(known_lower)) <= 2:
                dist = _edit_distance(normalized, known_lower)
                if 0 < dist <= 2:
                    return True

            if abs(len(part) - len(known_lower)) <= 1:
                dist = _edit_distance(part, known_lower)
                if dist == 1:
                    return True
        return False

    ext       = tldextract.extract(web_url)
    domain    = ext.domain.lower()
    subdomain = ext.subdomain.lower() if ext.subdomain else ""

    if check_part(domain):
        return True

    for part in subdomain.split("."):
        if part and part != "www":
            if check_part(part):
                return True

    return False