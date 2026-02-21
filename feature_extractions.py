import re
import math
import dns.exception
import dns.resolver
import dns.reversename
from itertools import combinations as combs
from difflib import SequenceMatcher
from geoip2.database import Reader
import os.path
import sys
import whois
import tldextract as tld
from bs4 import BeautifulSoup
import asyncio
import aiohttp

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
}
servers = ["1.1.1.1", "8.8.8.8", "208.67.222.222"]
resolvers = []

for server in servers:
    resolver = dns.resolver.Resolver(False)
    resolver.nameservers = [server]
    resolvers.append(resolver)

TTLs = list()


async def extract_features(domain):
    domain = re.sub(r"^www\d*", "", domain.lower()).lstrip(".")

    # domain_name_features
    length = len(domain)
    n_vowels = sum([c in domain for c in "aeiou"])
    n_vowel_chars = sum([domain.count(c) for c in "aeiou"])
    n_constant_chars = sum([domain.count(c) for c in "bcdfghjklmnpqrstvwxyz"])
    n_nums = sum([domain.count(c) for c in "0123456789"])
    n_other_chars = sum(
        [c not in "abcdefghijklmnopqrstuvwxyz0123456789." for c in domain]
    )
    probas = {i: domain.count(i) / len(domain) for i in set(domain)}
    entropy = -sum((p * math.log2(p)) for p in probas.values())

    domain_2 = domain.rstrip("\n")
    ext = tld.extract(domain_2)
    compact_domain = ".".join(filter(None, [ext.domain, ext.suffix]))

    # Concurrently fetch network-bound features
    ns_names_task = asyncio.to_thread(__get_rr, domain, "NS")
    mx_names_task = asyncio.to_thread(__get_rr, domain, "MX")
    ips_task = asyncio.to_thread(__get_rr, domain, "A", True)

    life_time_task = asyncio.to_thread(get_life_time, compact_domain)
    n_labels_task = get_n_labels(domain_2, compact_domain)

    ns_names, mx_names, ips, life_time, n_labels = await asyncio.gather(
        ns_names_task, mx_names_task, ips_task, life_time_task, n_labels_task
    )

    n_ns = len(ns_names)
    n_mx = len(mx_names)
    ns_similarity = get_ns_similarity(ns_names, ips)

    n_countries = await asyncio.to_thread(get_n_countries, ips)

    features_array = [
        length,
        n_ns,
        n_vowels,
        life_time,
        n_vowel_chars,
        n_constant_chars,
        n_nums,
        n_other_chars,
        entropy,
        n_mx,
        ns_similarity,
        n_countries,
        n_labels,
    ]
    return features_array


def __get_rr(domain, _type, ttl=False):
    names = set()
    for resolver in resolvers:
        try:
            records = resolver.resolve(domain, _type)
            for record in records:
                names.add(str(record))
            if ttl:
                TTLs.append(records.rrset.ttl)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
            dns.name.LabelTooLong,
        ):
            pass
    return names


def get_n_ptr(ips):
    cloudflare = dns.resolver.Resolver()
    cloudflare.nameservers = ["1.1.1.1"]
    ptr_names = set()
    for ip in ips:
        rev_name = dns.reversename.from_address(ip)
        try:
            ptr_records = cloudflare.resolve(rev_name, "PTR")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            continue
        for record in ptr_records:
            ptr_names.add(str(record))
    return len(ptr_names)


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_ns_similarity(ns_names, ips):
    if len(ns_names) > 2:
        similarities = list()
        all_combs = combs(ns_names, 2)
        for comb in all_combs:
            similarities.append(similarity(*comb))
        return sum(similarities) / len(similarities)
    elif len(ips) == 0 or len(ns_names) == 0:
        return 0.0
    else:
        return 1.0


def get_n_countries(ips):
    ip_countries = set()
    os.path.dirname(__file__)
    # dbpath = os.path.join(packagedir, '../../thirdparty/geoip/GeoLite2-City.mmdb')
    # city_reader = Reader(dbpath)
    try:
        city_reader = Reader("GeoLite2-City.mmdb")
        for ip in ips:
            try:
                city_resp = city_reader.city(ip)
                ip_countries.add(city_resp.country.iso_code)
            except Exception:
                pass
    except Exception:
        pass

    return len(ip_countries)


def __get_whois(compact_domain):
    expire = ""
    create = ""
    update = ""
    try:
        sys.stdout = open(os.devnull, "w")
        w = whois.whois(compact_domain)
        sys.stdout = sys.__stdout__
        if w.creation_date:
            if isinstance(w.creation_date, list):
                create = w.creation_date[0]
            elif isinstance(w.creation_date, str):
                pass
            else:
                create = w.creation_date
            if isinstance(create, str):
                create = None
        if w.updated_date:
            if isinstance(w.updated_date, list):
                update = w.updated_date[0]
            elif isinstance(w.updated_date, str):
                pass
            else:
                update = w.updated_date
            if isinstance(update, str):
                update = None
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                expire = w.expiration_date[0]
            elif isinstance(w.expiration_date, str):
                pass
            else:
                expire = w.expiration_date
            if isinstance(expire, str):
                expire = None
    except Exception:
        # Handle all whois errors (domain not found, network issues, etc.)
        sys.stdout = sys.__stdout__
        pass
    __whois = True

    return __whois, expire, create, update


def get_life_time(compact_domain):
    __whois, expire, create, update = __get_whois(compact_domain)
    if expire and create:
        td = expire - create
        return td.days
    else:
        return 0


def get_active_time(compact_domain):
    __whois, expire, create, update = __get_whois(compact_domain)
    if update and create:
        td = update - create
        return td.days
    else:
        return get_life_time(compact_domain)


async def get_html(url):
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get("http://" + url, timeout=5) as resp:
                if resp.status == 200:
                    return await resp.read()
                return None
    except Exception:
        print("get_html:error")
        return None


async def get_n_labels(domain, compact_domain):
    html = None
    try:
        html = await get_html(domain)
    except Exception:
        pass

    if not html:
        try:
            html = await get_html(compact_domain)
        except Exception:
            print("get_n_labels:error")
            pass

    if html:
        try:
            soup = BeautifulSoup(html, features="html.parser")
            return len(soup.find_all())
        except Exception:
            print("get_n_labels_if_html:error")
            return 0
    else:
        return 0
