import os
import unittest
from unittest import mock
from core import impersonation
from core.impersonation import (
    sanitize_keywords,
    decompose_keyword,
    generate_keyword_dorks,
    generate_impersonation_recon_suite,
    capture_domains_from_keywords,
)
from core.sources import SourceError


class TestImpersonation(unittest.TestCase):
    def test_sanitize_keywords(self):
        raw = "paypal, https://binance.com/login,  netflix , cyfirma\nmetamask.io; info@lntrealty.com | www.gi-de.com/en/"
        kws = sanitize_keywords(raw)
        self.assertEqual(kws, ["paypal", "binance.com", "netflix", "cyfirma", "metamask.io", "lntrealty.com", "gi-de.com"])

    def test_generate_keyword_dorks(self):
        res = generate_keyword_dorks("paypal")
        self.assertEqual(res["keyword"], "paypal")

        # 1. FOFA: '=' is a token match; '*' wildcards only work with the '*=' operator
        self.assertEqual(res["fofa"]["domain_wildcard"], 'host="paypal"')
        self.assertEqual(res["fofa"]["domain_contains"], 'host*="*paypal*"')
        self.assertIn('body="paypal"', res["fofa"]["body_content"])
        self.assertIn('is_domain=true', res["fofa"]["master"])
        self.assertNotIn('="*', res["fofa"]["master"])

        # 2. Censys Platform (CenQL): no wildcards
        self.assertNotIn('*', res["censys"]["domain_wildcard"])
        self.assertNotIn('*', res["censys"]["cert_wildcard"])
        self.assertEqual(res["censys"]["domain_wildcard"], 'web.hostname: "paypal"')
        self.assertEqual(res["censys"]["cert_wildcard"], 'cert.names: "paypal"')

        # 3. URLScan: free-tier master (page.title + trailing wildcard), no non-existent page.body field
        self.assertIn('page.domain:paypal*', res["urlscan"]["domain_wildcard"])
        self.assertIn('page.title:"paypal"', res["urlscan"]["master"])
        self.assertEqual(res["urlscan"]["body_content"], 'text.content:"paypal"')
        for q in res["urlscan"].values():
            self.assertNotIn("page.body", q)
        self.assertNotIn("page.domain.keyword", res["urlscan"]["master"])

        # 4. Shodan
        self.assertEqual(res["shodan"]["cert_wildcard"], 'ssl.cert.subject.cn:paypal')
        self.assertEqual(res["shodan"]["title_spoof"], 'http.title:"paypal"')
        self.assertEqual(res["shodan"]["body_content"], 'http.html:"paypal"')
        self.assertNotIn(' OR ', res["shodan"]["master"])

        # Search URLs
        self.assertTrue(res["fofa"]["master_url"].startswith("https://fofa.info/result?qbase64="))
        self.assertTrue(res["censys"]["master_url"].startswith("https://platform.censys.io/search?q="))
        self.assertTrue(res["urlscan"]["master_url"].startswith("https://urlscan.io/search/#"))
        self.assertTrue(res["shodan"]["master_url"].startswith("https://www.shodan.io/search?query="))

    def test_domain_input_excludes_legit_domain(self):
        res = generate_keyword_dorks("paypal.com")
        self.assertEqual(res["decomposition"]["legit_domain"], "paypal.com")
        self.assertIn('domain!="paypal.com"', res["fofa"]["master"])
        self.assertIn("NOT page.apexDomain:paypal.com", res["urlscan"]["master"])
        self.assertIn("-hostname:paypal.com", res["shodan"]["master"])

    def test_multi_part_tld_and_hyphenated_domains(self):
        bbc = decompose_keyword("bbc.co.uk")
        self.assertEqual(bbc["tokens"], ["bbc"])
        self.assertEqual(bbc["legit_domain"], "bbc.co.uk")

        gide = decompose_keyword("gi-de.com")
        self.assertEqual(gide["tokens"], ["gi-de", "gide"])
        for short in ("gi", "de", "co", "com"):
            self.assertNotIn(short, gide["tokens"])

    def test_ampersand_brands(self):
        att = decompose_keyword("AT&T")
        self.assertIn("att", att["tokens"])
        self.assertNotIn("at", att["tokens"])
        spaced = decompose_keyword("L & T Island Cove")
        self.assertIn("L&T Island Cove", spaced["titles"])
        self.assertIn("Island Cove", spaced["titles"])
        self.assertIn("lnt", spaced["tokens"])

    def test_generate_impersonation_recon_suite(self):
        suite = generate_impersonation_recon_suite("paypal, binance")
        self.assertEqual(suite["total_keywords"], 2)
        for p in ("fofa", "censys", "urlscan", "shodan"):
            self.assertIn(p, suite["master_queries"])

        fofa_q = suite["master_queries"]["fofa"]["query"]
        self.assertIn('host="paypal"', fofa_q)
        self.assertIn('host="binance"', fofa_q)

        censys_q = suite["master_queries"]["censys"]["query"]
        self.assertNotIn('*', censys_q)
        self.assertEqual(censys_q, 'web.hostname: {"paypal", "binance"}')

        urlscan_q = suite["master_queries"]["urlscan"]["query"]
        self.assertIn('page.domain:paypal*', urlscan_q)
        self.assertIn('page.domain:binance*', urlscan_q)

        # Shodan ORs comma-separated values of a single filter
        self.assertEqual(suite["master_queries"]["shodan"]["query"], "ssl.cert.subject.cn:paypal,binance")

    def test_exclusion_applies_to_whole_or_group(self):
        suite = generate_impersonation_recon_suite("paypal.com, binance.com")
        mq = suite["master_queries"]["urlscan"]
        for key in ("query", "title_query", "domain_query", "body_query"):
            q = mq[key]
            self.assertTrue(q.startswith("("), q)
            self.assertTrue(q.endswith("NOT page.apexDomain:(paypal.com OR binance.com)"), q)

    def test_project_decomposition_lnt(self):
        res = generate_keyword_dorks("L&T Avinya Enclave")
        self.assertEqual(res["keyword"], "L&T Avinya Enclave")

        self.assertIn('L&T Avinya Enclave', res["decomposition"]["titles"])
        self.assertIn('Avinya Enclave', res["decomposition"]["titles"])

        self.assertIn('avinya', res["decomposition"]["tokens"])
        self.assertIn('enclave', res["decomposition"]["tokens"])
        self.assertIn('lnt', res["decomposition"]["tokens"])
        self.assertEqual(res["decomposition"]["project_slug"], "avinya-enclave")

        self.assertNotIn('*', res["censys"]["domain_wildcard"])
        self.assertIn('"avinya"', res["censys"]["domain_wildcard"])
        self.assertIn('"enclave"', res["censys"]["domain_wildcard"])

        urlscan_title = res["urlscan"]["title_spoof"]
        self.assertIn('page.title:"L&T Avinya Enclave"', urlscan_title)
        self.assertIn('page.title:"Avinya Enclave"', urlscan_title)

        urlscan_domain = res["urlscan"]["domain_wildcard"]
        self.assertNotIn('page.domain:L&T', urlscan_domain)
        self.assertIn('page.domain:avinya*', urlscan_domain)
        self.assertIn('page.domain:enclave*', urlscan_domain)
        self.assertIn('page.domain:avinya-enclave*', urlscan_domain)

        self.assertEqual(res["shodan"]["title_spoof"], 'http.title:"Avinya Enclave"')
        self.assertEqual(res["shodan"]["cert_wildcard"], 'ssl.cert.subject.cn:lnt,avinya,enclave')
        self.assertEqual(res["shodan"]["body_content"], 'http.html:"Avinya Enclave"')
        self.assertEqual(res["bare_keyword"], "avinya")

        suite = generate_impersonation_recon_suite("L&T Avinya Enclave, L&T The Gateway, lntrealty.com")
        self.assertEqual(suite["total_keywords"], 3)
        mq = suite["master_queries"]["urlscan"]
        self.assertIn('page.title:"L&T Avinya Enclave"', mq["title_query"])
        self.assertIn('page.domain:avinya*', mq["domain_query"])
        self.assertIn("body_query", mq)

    def test_all_domain_capture_dorks_single_and_multi(self):
        res = generate_keyword_dorks("paypal.com")
        # FOFA all_domains uses substring wildcards across domain/host/cert without status_code="200"
        fofa_all = res["fofa"]["all_domains"]
        self.assertIn('domain*="*paypal*"', fofa_all)
        self.assertIn('host*="*paypal*"', fofa_all)
        self.assertIn('cert*="*paypal*"', fofa_all)
        self.assertIn('domain!="paypal.com"', fofa_all)
        self.assertNotIn('status_code="200"', fofa_all)
        self.assertNotIn('status_code="200"', res["fofa"]["master"])

        # Censys all_domains uses case-insensitive CenQL regex + domain exclusion
        censys_all = res["censys"]["all_domains"]
        self.assertIn('web.hostname =~ "(?i).*paypal.*"', censys_all)
        self.assertIn('cert.names =~ "(?i).*paypal.*"', censys_all)
        self.assertIn('host.dns.names =~ "(?i).*paypal.*"', censys_all)
        self.assertIn('and not (', censys_all)

        # URLScan all_domains uses keyword infix/prefix/suffix + task.domain.keyword;
        # free-tier master includes page.url:paypal* so hyphenated secure-paypal.com matches anonymously
        us_all = res["urlscan"]["all_domains"]
        self.assertIn("page.domain.keyword:*paypal*", us_all)
        self.assertIn("task.domain.keyword:*paypal*", us_all)
        self.assertIn("AND NOT page.apexDomain:paypal.com", us_all)
        self.assertIn("page.url:paypal*", res["urlscan"]["master"])

        # Shodan exposes hostname PTR + broad SSL (CN+SAN) + Cert CN
        self.assertEqual(res["shodan"]["all_domains"], "hostname:paypal -hostname:paypal.com")
        self.assertEqual(res["shodan"]["ssl_all"], 'ssl:"paypal" -hostname:paypal.com')

        # crt.sh and search engines included
        self.assertEqual(res["crtsh"]["query"], "%paypal%")
        self.assertIn("crt.sh/?q=%25paypal%25", res["crtsh"]["url"])
        self.assertIn("inurl:paypal", res["search_engines"]["inurl"]["query"])

    def test_short_brand_and_generic_phrase_decomposition(self):
        # Uppercase / ampersand brand + generic word keeps compound slugs
        hdfc = decompose_keyword("HDFC Bank")
        self.assertIn("hdfc", hdfc["tokens"])
        self.assertIn("hdfcbank", hdfc["compound_slugs"])
        self.assertIn("hdfc-bank", hdfc["compound_slugs"])

        lnt_realty = decompose_keyword("L&T Realty")
        self.assertIn("lnt", lnt_realty["tokens"])
        self.assertIn("lntrealty", lnt_realty["compound_slugs"])
        self.assertIn("lnt-realty", lnt_realty["compound_slugs"])

        # Lowercase 3-char brand anchor ("sbi card") keeps "sbi" instead of dropping it for "card"
        sbi = decompose_keyword("sbi card")
        self.assertIn("sbi", sbi["tokens"])
        self.assertNotIn("card", sbi["tokens"])
        self.assertIn("sbicard", sbi["compound_slugs"])

        # Phrase made purely of generic words avoids standalone *global* / *tech* flooding
        generic = decompose_keyword("Global Tech Solutions")
        self.assertNotIn("global", generic["tokens"])
        self.assertNotIn("tech", generic["tokens"])
        self.assertIn("globaltechsolutions", generic["tokens"])
        self.assertIn(["global", "tech", "solutions"], generic["cooccurrence_groups"])

        # Co-occurrence pairs appear in all_domains queries
        gd = generate_keyword_dorks("Global Tech Solutions")
        self.assertIn('host*="*global*" && host*="*tech*"', gd["fofa"]["all_domains"])
        self.assertIn("page.domain.keyword:*global* AND page.domain.keyword:*tech*", gd["urlscan"]["all_domains"])

    def test_substring_minimization_and_variants(self):
        # Substring terms drop redundant superstrings when 'avinya' already matches *avinyaenclave*
        suite = generate_impersonation_recon_suite("L&T Avinya Enclave")
        self.assertIn("avinya", suite["all_substring_terms"])
        self.assertNotIn("avinyaenclave", suite["all_substring_terms"])
        self.assertNotIn("avinya-enclave", suite["all_substring_terms"])
        self.assertIn("avinya-enclave", suite["all_host_terms"])

        # Multi-keyword Censys regex combines tokens cleanly in one alternation
        multi = generate_impersonation_recon_suite("paypal, binance")
        self.assertIn('web.hostname =~ "(?i).*(paypal|binance).*"', multi["master_queries"]["censys"]["all_domains_query"])

        # Typosquat, hyphen-split, and IDN Punycode evasion variants
        var_res = generate_keyword_dorks("paypal", include_variants=True)
        self.assertTrue(var_res["decomposition"]["variants"])
        self.assertIn("paypa1", var_res["decomposition"]["variants"])
        self.assertIn("pay-pal", var_res["decomposition"]["variants"])
        self.assertIn("pypal", var_res["decomposition"]["punycode_skeletons"])
        self.assertIn('domain*="*paypa1*"', var_res["fofa"]["all_domains"])
        self.assertIn("page.domain.keyword:*paypa1*", var_res["urlscan"]["all_domains"])

        # Attacker-vector packs: scam_lures, free_hosting, idn_homoglyph, deep exhaustive, search engines
        self.assertIn("page.domain:xn--pypal*", var_res["urlscan"]["idn_homoglyph"])
        self.assertIn("pages.dev", var_res["urlscan"]["free_hosting"])
        self.assertIn("kyc", var_res["urlscan"]["scam_lures"])
        self.assertIn("task.url:*paypal*", var_res["urlscan"]["exhaustive"])
        self.assertIn("filename:*paypal*", var_res["urlscan"]["exhaustive"])

        self.assertIn('host*="xn--"', var_res["fofa"]["idn_homoglyph"])
        self.assertIn('body*="*paypal*"', var_res["fofa"]["exhaustive"])
        self.assertIn('header*="*paypal*"', var_res["fofa"]["exhaustive"])
        self.assertIn('seed phrase', var_res["fofa"]["scam_lures"])
        self.assertIn('domain="pages.dev"', var_res["fofa"]["free_hosting"])

        self.assertIn('web.endpoints.http.body =~', var_res["censys"]["exhaustive"])
        self.assertIn('xn--.*', var_res["censys"]["idn_homoglyph"])
        self.assertIn(r'pages\\.dev', var_res["censys"]["free_hosting"])
        self.assertIn('http.html:"password"', var_res["shodan"]["scam_lures"])

        for k in ("inurl", "credential_lure", "wildcard_site", "free_hosting", "scam_campaigns", "social_and_apps", "leaks_and_redirects"):
            self.assertIn(k, var_res["search_engines"])

    @mock.patch.dict(os.environ, {"FREE_ONLY_MODE": "0"})  # exercises the paid-platform path

    def test_capture_domains_from_keywords(self):
        fake_ct = {
            "hosts": {
                "www.paypal.com": {"first_seen": "2020-01-01", "last_seen": "2026-11-01", "issuer": "DigiCert", "certs": 5},
                "secure-paypal.xyz": {"first_seen": "2026-11-10", "last_seen": "2026-11-20", "issuer": "LE", "certs": 1},
                "xn--pypal-bqa.com": {"first_seen": "2026-11-18", "last_seen": "2026-11-24", "issuer": "LE", "certs": 1},
                "unrelated.com": {"first_seen": "2026-11-01", "last_seen": "2026-11-02", "issuer": "LE", "certs": 1},
            },
            "error": None,
        }
        fake_us = [
            {"host": "mypaypal-login.com", "ip": "1.2.3.4", "url": "https://mypaypal-login.com/", "title": "Log in", "time": "2026-11-22", "source": "urlscan", "extra": {}},
            {"host": "secure-paypal.xyz", "ip": "5.6.7.8", "url": "https://secure-paypal.xyz/", "title": "Verify", "time": "2026-11-23", "source": "urlscan", "extra": {}},
        ]
        # Simulate FOFA key failing via with_rotation-wrapped exhausted error ("plan does not allow") on *= then falling back
        fofa_calls = []
        def fake_fofa(q, size=100):
            fofa_calls.append(q)
            if "*=" in q:
                raise SourceError("key failed, last error: FOFA: your FOFA plan does not allow this query (code 820001)", kind="exhausted")
            return [{"host": "paypal-verify.top", "ip": "9.9.9.9", "url": None, "title": "PayPal", "time": "", "source": "fofa", "extra": {}}]

        fake_feed = {"hits": [{"host": "paypa1-support.com", "url": "http://paypa1-support.com", "feed": "openphish", "feed_name": "OpenPhish"}], "status": [], "errors": []}
        fake_dns = {"paypal-kyc.com": {"domain": "paypal-kyc.com", "a": ["2.2.2.2"], "aaaa": [], "registered": True}}

        with mock.patch.object(impersonation, "crtsh_search", return_value=fake_ct), \
                mock.patch.object(impersonation.feeds, "match", return_value=fake_feed), \
                mock.patch.object(impersonation, "resolve_domains", return_value=fake_dns), \
                mock.patch.object(impersonation.config, "get", side_effect=lambda k: "k" if k == "FOFA_KEY" else None), \
                mock.patch.object(impersonation.config, "is_configured", side_effect=lambda s: s in ("urlscan", "fofa")), \
                mock.patch.dict(impersonation.SEARCHERS, {"urlscan": lambda q, size=100: fake_us, "fofa": fake_fofa}):
            out = capture_domains_from_keywords("paypal.com", use_dns=True)

        doms = [d["domain"] for d in out["domains"]]
        self.assertNotIn("www.paypal.com", doms)   # legit domain excluded
        self.assertNotIn("unrelated.com", doms)    # non-matching CT row filtered
        self.assertIn("secure-paypal.xyz", doms)
        self.assertIn("xn--pypal-bqa.com", doms)   # IDN punycode matched via skeleton
        self.assertIn("mypaypal-login.com", doms)
        self.assertIn("paypal-verify.top", doms)
        self.assertIn("paypa1-support.com", doms)
        self.assertIn("paypal-kyc.com", doms)      # caught via live DNS probe
        # Merged sources on duplicate domain
        merged = next(d for d in out["domains"] if d["domain"] == "secure-paypal.xyz")
        self.assertEqual(set(merged["sources"]), {"crt.sh", "urlscan"})
        self.assertEqual(len(fofa_calls), 2)


if __name__ == "__main__":
    unittest.main()
