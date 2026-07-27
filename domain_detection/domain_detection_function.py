import logging
import re
import socket
import ssl
import traceback
import requests
import dns.resolver
import tldextract
import whois
from datetime import datetime, timezone
import pandas as pd
from dateutil import parser as date_parser
from dateutil.relativedelta import relativedelta
from detectionattrenum import DomainDetectionError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rule_parser import DomainRule

logging.getLogger('whois.whois').setLevel(logging.CRITICAL)

headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }

def suspicious_ssl_cert(web_url, cert_none_mode=False, timeout=5, port=443):

    conn: ssl.SSLSocket = None
    try:
        ext = tldextract.extract(web_url)
        if ext.domain == "www":
            domain = ext.suffix
        else:
            if ext.subdomain:
                domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
            else:
                domain = f"{ext.domain}.{ext.suffix}"

        domain = domain.strip().lower()
        context = ssl.create_default_context()

        if cert_none_mode:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(timeout)
        conn.connect((domain, port))

        def matches(domain, pattern):
            if pattern.startswith("*."):
                ext = tldextract.extract(pattern)
                suffix = f"{ext.domain}.{ext.suffix}"
                return domain.endswith("." + suffix) and domain != suffix
            return domain == pattern

        if cert_none_mode:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            der_cert = conn.getpeercert(binary_form=True)  # ✅ close 之前
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_list = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                san_list = []
        else:
            cert_dict = conn.getpeercert()                 # ✅ close 之前
            cn = dict(x[0] for x in cert_dict['subject']).get('commonName', '')
            san_list = [s[1] for s in cert_dict.get('subjectAltName', []) if s[0] == 'DNS']

       
        matched = any(matches(domain, s) for s in san_list + [cn])
        return not matched

    except ssl.SSLCertVerificationError:
        return True 
    except ssl.SSLError as e:
       
        logging.debug(f"suspicious_ssl SSL error for {web_url}: {e}")
        return True
    except socket.gaierror as e:
        
        logging.debug(f"suspicious_ssl DNS resolution failed for {web_url}: {e}")
        return True

    except (socket.timeout, TimeoutError) as e:
        
        logging.debug(f"suspicious_ssl timeout for {web_url}: {e}")
        return True

    except ConnectionRefusedError as e:
        
        logging.debug(f"suspicious_ssl connection refused for {web_url}: {e}")
        return True
    
    except Exception as e:
        logging.debug(f"suspicious_ssl {e}")
        raise
     
    finally:
        if conn:
            conn.close()

def check_domain_age(domain_rule: DomainRule, web_url: str) -> bool:

    try:
        ext = tldextract.extract(web_url)
        registered_domain = f"{ext.domain}.{ext.suffix}"

        if not registered_domain or registered_domain == ".":
            return False

        w = whois.whois(registered_domain)
        if not w or not w.creation_date:
            return False

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return False

        # Normalize string dates
        if isinstance(creation_date, str):
            try:
                creation_date = date_parser.parse(creation_date)
            except (ValueError, OverflowError):
                return False

        if not isinstance(creation_date, datetime):
            return False

        # Normalize timezone: make both tz-aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        today = datetime.now(timezone.utc)
        total_months = (
            (today.year - creation_date.year) * 12
            + (today.month - creation_date.month)
        )

        return total_months < domain_rule.domain_age_below_month_yparam

    except Exception as e:
        logging.debug(f"check_domain_age {web_url}: {e}")
        raise



def check_domain_age_rdap(domain_rule: DomainRule, web_url: str) -> bool:
    """
    Returns True if the domain age is <= domain_rule.domain_age_below_month,
    False if older or if the age cannot be determined.
    Tries RDAP first, falls back to WHOIS.
    """
    try:
        ext = tldextract.extract(web_url)
        registered_domain = f"{ext.domain}.{ext.suffix}"
        if not registered_domain or registered_domain == ".":
            return False

        creation_date = None

        # --- RDAP ---
        try:
            response = requests.get(
                f"https://rdap.org/domain/{registered_domain}",
                timeout=10,
                headers={"Accept": "application/rdap+json"},
            )
            response.raise_for_status()
            for event in response.json().get("events", []):
                if event.get("eventAction") == "registration":
                    creation_date = date_parser.parse(event.get("eventDate", ""))
                    break
        except Exception as e:
            logging.debug(f"RDAP failed for {registered_domain}: {e}")

        # --- WHOIS fallback ---
        if creation_date is None:
            try:
                socket.setdefaulttimeout(10)
                w = whois.whois(registered_domain)
                if w and w.creation_date:
                    raw = w.creation_date
                    if isinstance(raw, list):
                        raw = raw[0]
                    if isinstance(raw, str):
                        raw = date_parser.parse(raw)
                    if isinstance(raw, datetime):
                        creation_date = raw
            except Exception as e:
                logging.debug(f"WHOIS failed for {registered_domain}: {e}")

        if creation_date is None:
            return False

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        today = datetime.now(timezone.utc)
        total_months = (
            (today.year - creation_date.year) * 12
            + (today.month - creation_date.month)
        )
        return total_months <= domain_rule.domain_age_below_month_yparam

    except Exception as e:
        logging.debug(f"check_domain_age {web_url}: {e}")
        raise


def get_pagerank_localservice(url) -> float:
    api_base: str = "http://127.0.0.1:8000"
    response = requests.get(f"{api_base}/pagerank", params={"url": url})
    response.raise_for_status()
    return response.json()

def load_pagerank(csv_path: str) -> dict:
    """一次性加载 CSV 到 dict"""
    df = pd.read_csv(csv_path, usecols=["Domain", "open_rank_score"])
    df["Domain"] = df["Domain"].str.strip().str.lower()
    df["open_rank_score"] = pd.to_numeric(df["open_rank_score"], errors="coerce").fillna(0.0)
    return dict(zip(df["Domain"], df["open_rank_score"]))



def get_pagerank(web_url: str, pagerank: dict) -> float:
    """
    查询域名 PageRank 分数
    Returns 0.0 if not found

    NOTE: assumes `pagerank` stores RAW page_rank_decimal values (0-10 scale).
    Base domain is checked first (this is what's normally cached), with the
    full subdomain string as a fallback -- same priority as get_domain_rank.
    """
    ext = tldextract.extract(web_url)

    if ext.domain == "www":
        # e.g. www.gov.uk -> tldextract treats "gov.uk" as the suffix,
        # so the meaningful "domain" here is actually the suffix.
        domain = ext.suffix
        with_subdomain = ""
    else:
        domain = f"{ext.domain}.{ext.suffix}"
        with_subdomain = ""
        if ext.subdomain:
            with_subdomain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"

    domain = domain.strip().lower()
    with_subdomain = with_subdomain.strip().lower()

    if domain in pagerank:                                     # base domain checked FIRST
        return pagerank[domain] / 10

    if with_subdomain and with_subdomain in pagerank:          # fallback to full subdomain string
        return pagerank[with_subdomain] / 10

    with open("rank.txt", "a") as file:
        file.write(f"cannot find :{web_url}\n")

    return 0.0


def find_ns(web_url: str) -> list[str]:
    ext = tldextract.extract(web_url)

    if ext.domain == "www":
        domain = ext.suffix
    else:
        domain = f"{ext.domain}.{ext.suffix}"

    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(domain, "NS")
        return [str(rdata).lower() for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logging.debug(f"find_ns: NXDOMAIN {domain}")
    except dns.resolver.NoAnswer:
        logging.debug(f"find_ns: no NS record {domain}")
    except dns.resolver.NoNameservers:
        logging.debug(f"find_ns: NS servers unreachable {domain}")
    except dns.exception.Timeout:
        logging.debug(f"find_ns: timeout {domain}")

    return []


def get_page_rank_by_api(domain_rule: DomainRule, web_url: str) -> bool:
    try:
        ext = tldextract.extract(web_url)
        if ext.subdomain:
            domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
        else:
            domain = f"{ext.domain}.{ext.suffix}"


        api_key = domain_rule.page_rank_yparam["api_key"]

        response = requests.get(
            "https://openpagerank.com/api/v1.0/getPageRank",
            headers={"API-OPR": api_key},
            params={"domains[]": domain},
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        result = data['response'][0]

        if result['page_rank_decimal']:
            page_rank_score = float(result['page_rank_decimal']) / 10
            return page_rank_score
        
        return 0.0

    except KeyError as e:
        logging.error(f"Missing key in page rank settings or response: {e}")
        raise
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error when fetching page rank for {web_url}: {e}")
        raise
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error when fetching page rank for {web_url}: {e}")
        raise
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout when fetching page rank for {web_url}: {e}")
        raise
    except requests.exceptions.RequestException as e:
        logging.error(f"Unexpected request error for {web_url}: {e}")
        raise
    except (ValueError, IndexError) as e:
        logging.error(f"Failed to parse page rank response for {web_url}: {e}")
        raise
    except Exception as e:
        logging.error(f" check_page_rank_deficient: {e}")
        raise
    
    # print(f"Status Code: {data["status_code"]}")
    # print(f"Domain: {result['domain']}")
    # print(f"Page Rank Score: {result['page_rank_integer']} / 10")
    # print(f"Page Rank Decimal: {result['page_rank_decimal']}")
    # print(f"Global Rank: {result['rank']}")


def check_dns_records(domain: str, cases: list) -> dict:
    common_mail_subdomains = ["send", "mail", "send.auth", "mg", "em", "mailer", "bounce"]

    esp_spf_signatures = {
        "amazonses.com": "Amazon SES / Resend",
        "sendgrid.net": "SendGrid",
        "mailgun.org": "Mailgun",
        "_spf.google.com": "Google Workspace",
        "spf.protection.outlook.com": "Microsoft 365",
    }

    result = {}

    # CAA, DNSKEY (simple presence check)
    for record_type in ("CAA", "DNSKEY"):
        if record_type in cases:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = True if len(answers) > 0 else False
            except Exception:
                result[record_type] = False

    # MX (apex first, then common ESP subdomains)
    if "MX" in cases:
        mx_info = {"status": "none", "records": [], "subdomain": None}

        try:
            answers = dns.resolver.resolve(domain, "MX")
            records = [str(r.exchange) for r in answers]
            if records:
                mx_info["status"] = "apex"
                mx_info["records"] = records
        except Exception:
            pass

        if mx_info["status"] == "none":
            for sub in common_mail_subdomains:
                try:
                    answers = dns.resolver.resolve(f"{sub}.{domain}", "MX")
                    records = [str(r.exchange) for r in answers]
                    if records:
                        mx_info["status"] = "subdomain"
                        mx_info["subdomain"] = sub
                        mx_info["records"] = records
                        break
                except Exception:
                    continue

        result["MX"] = mx_info if mx_info["status"] != "none" else None

    # SPF
    if "SPF" in cases:
        spf_info = None
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
            if spf_records:
                provider = None
                for sig, prov in esp_spf_signatures.items():
                    if any(sig in s for s in spf_records):
                        provider = prov
                        break
                spf_info = {"present": True, "provider": provider}
        except Exception:
            pass
        result["SPF"] = spf_info

    # DMARC
    if "DMARC" in cases:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            result["DMARC"] = True if len(answers) > 0 else False
        except Exception:
            result["DMARC"] = False

    return result

def is_missing_dns_records(web_url: str, required_records: list) -> bool:
    ext = tldextract.extract(web_url)
    if ext.domain == "www":
      # www.gov.uk 这类情况，domain 实际上是 suffix
        domain = ext.suffix
    else:
        domain = f"{ext.domain}.{ext.suffix}"
    records = check_dns_records(domain,required_records)
    return all(not records.get(r) for r in required_records)



def check_registration_period(web_url: str,year:int) -> bool:
    ext = tldextract.extract(web_url)
    if ext.domain == "www":
      # www.gov.uk 这类情况，domain 实际上是 suffix
        domain = ext.suffix
    else:
        domain = f"{ext.domain}.{ext.suffix}"

    try:
        w   = whois.whois(domain)
        raw = dict(w)

        creation = raw.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, str):
            creation = datetime.fromisoformat(creation)
        if creation and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        expiration = raw.get("expiration_date")
        if isinstance(expiration, list):
            expiration = expiration[0]
        if isinstance(expiration, str):
            expiration = datetime.fromisoformat(expiration)
        if expiration and expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)

        if creation is None or expiration is None:
            return False

      
        return expiration <= creation + relativedelta(years=1)


    except Exception as e:
        logging.error(f"check_registration_period {domain}: {e}")
        return DomainDetectionError.REQUEST_ERROR



def compare_redirect_page_rank(web_url:str,destination_url:str,trigger_rank:float,page_rank_dict:dict = {}):
    try:
            
        ori_page_rank = get_pagerank_localservice(web_url)
        
        if ori_page_rank > trigger_rank:
            return False
       
        redirect_page_rank = get_pagerank_localservice(destination_url)
        
      
        
        return redirect_page_rank > ori_page_rank
        
    except Exception as e:
        logging.error(f" check_page_rank_deficient: {e}")
        raise


def compare_redirect_page_rank_local_dict(web_url:str,destination_url:str,trigger_rank:float, page_rank_dict:dict = {}):
    try:
            
   
        ori_page_rank = get_pagerank(web_url,page_rank_dict)
        
        if ori_page_rank > trigger_rank:
            return False
        
        redirect_page_rank = get_pagerank(destination_url,page_rank_dict)
        
      
        return redirect_page_rank > ori_page_rank

    except Exception as e:
        logging.error(f" check_page_rank_deficient: {e}")
        raise