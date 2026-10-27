#!/usr/bin/env python3
"""
Potamus Security — recolha de ameaças a partir de fontes PÚBLICAS e LIVRES.

Fontes (sem conta, sem chave, sem licença):
  * CISA Known Exploited Vulnerabilities (KEV) — licença CC0 (domínio público).
  * NVD — National Vulnerability Database (NIST). Serviço público; pede apenas o aviso
    "This product uses the NVD API but is not endorsed or certified by the NVD."

Gera um RASCUNHO (não assinado) do definitions.json. O rascunho é aberto no
Potamus Assinador, revisto e assinado no computador da CodiPotamus — a chave
privada nunca passa por aqui.

Uso:
  python3 tools/build-definitions.py                 # atualização: últimos 14 dias
  python3 tools/build-definitions.py --days 730      # carga inicial: últimos 2 anos
  python3 tools/build-definitions.py --from-files nvd1.json [...] --kev kev.json   # testes, sem rede

Só usa a biblioteca padrão do Python 3.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "drafts", "definitions-draft.json")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."
UA = "PotamusSecurity-definitions/1.0 (+https://codipotamus.site)"

# NVD sem chave: 5 pedidos por 30 segundos. Fica-se bem abaixo disso.
NVD_PAUSE = 7
NVD_WINDOW_DAYS = 110  # a API aceita no máximo 120 dias por pedido

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------- rede


def http_json(url, tries=4):
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(30 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            if attempt < tries - 1:
                time.sleep(30 * (attempt + 1))
                continue
            raise


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_nvd(days):
    """CVEs com 'WordPress' modificadas nos últimos `days` dias, em janelas de 110 dias."""
    end = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    start = end - dt.timedelta(days=days)
    out = []
    win_start = start
    while win_start < end:
        win_end = min(win_start + dt.timedelta(days=NVD_WINDOW_DAYS), end)
        index = 0
        while True:
            q = urllib.parse.urlencode({
                "keywordSearch": "WordPress",
                "lastModStartDate": iso(win_start),
                "lastModEndDate": iso(win_end),
                "resultsPerPage": 2000,
                "startIndex": index,
            })
            data = http_json(NVD_URL + "?" + q)
            batch = data.get("vulnerabilities", [])
            out.extend(batch)
            total = int(data.get("totalResults", 0))
            index += len(batch)
            print(f"  NVD {win_start:%Y-%m-%d}..{win_end:%Y-%m-%d}: {index}/{total}", file=sys.stderr)
            time.sleep(NVD_PAUSE)
            if not batch or index >= total:
                break
        win_start = win_end
    return out


def fetch_nvd_ids(ids):
    out = []
    for cve in ids:
        data = http_json(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve}))
        out.extend(data.get("vulnerabilities", []))
        time.sleep(NVD_PAUSE)
    return out


# ---------------------------------------------------------------- análise

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,100}$")
REF_PATTERNS = [
    ("plugin", re.compile(r"https?://patchstack\.com/database/wordpress/plugin/([a-z0-9][a-z0-9_-]+)", re.I)),
    ("theme", re.compile(r"https?://patchstack\.com/database/wordpress/theme/([a-z0-9][a-z0-9_-]+)", re.I)),
    ("plugin", re.compile(r"https?://plugins\.trac\.wordpress\.org/changeset\?.*?(?:old|new)=\d+%40([a-z0-9][a-z0-9_-]+)", re.I)),
    ("plugin", re.compile(r"https?://(?:[a-z]{2,3}\.)?wordpress\.org/plugins/([a-z0-9][a-z0-9_-]+)", re.I)),
    ("plugin", re.compile(r"https?://plugins\.(?:trac|svn)\.wordpress\.org/(?:browser/|changeset/[^/]*/)?([a-z0-9][a-z0-9_-]+)", re.I)),
    ("theme", re.compile(r"https?://(?:[a-z]{2,3}\.)?wordpress\.org/themes/([a-z0-9][a-z0-9_-]+)", re.I)),
    ("theme", re.compile(r"https?://themes\.(?:trac|svn)\.wordpress\.org/(?:browser/)?([a-z0-9][a-z0-9_-]+)", re.I)),
]
NOT_SLUGS = {"tags", "trunk", "branches", "browser", "changeset", "search", "developers", "readme"}

# Formulações habituais dos avisos de vulnerabilidades de plugins WordPress.
UP_TO_INCL = [
    re.compile(r"versions? up to,? and including,? ([0-9][0-9a-z.\-]*)", re.I),
    re.compile(r"from n/a through (?:<= ?)?([0-9][0-9a-z.\-]*)", re.I),
    re.compile(r"through (?:version )?(?:<= ?)?([0-9][0-9a-z.\-]*)", re.I),
    re.compile(r"<= ?([0-9][0-9a-z.\-]*)"),
]
BEFORE = [
    re.compile(r"before (?:version )?([0-9][0-9a-z.\-]*)", re.I),
    re.compile(r"prior to (?:version )?([0-9][0-9a-z.\-]*)", re.I),
    re.compile(r"< ?([0-9][0-9a-z.\-]*)"),
]


def clean_version(v):
    v = (v or "").strip().rstrip(".,;)")
    return v if re.match(r"^[0-9][0-9a-z.\-]*$", v, re.I) else ""


def description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def severity(cve):
    best = 0.0
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []) or []:
            score = float((m.get("cvssData") or {}).get("baseScore") or 0)
            best = max(best, score)
    if best >= 9:
        return "critical", best
    if best >= 7:
        return "high", best
    if best >= 4:
        return "medium", best
    if best > 0:
        return "low", best
    return "", 0.0


def kind_from_text(text):
    t = text.lower()
    if " theme for wordpress" in t or " wordpress theme" in t or "theme for wp" in t:
        return "theme"
    return "plugin"


def from_cpe(cve):
    """Produtos WordPress nas configurações da NVD: [(slug, max_incl, fixed_in)]."""
    found = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = (m.get("criteria") or "").split(":")
                # cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:...
                if len(parts) < 11 or parts[2] != "a" or parts[10].lower() != "wordpress":
                    continue
                slug = parts[4].lower().replace("_", "-").replace("\\", "")
                version = parts[5]
                max_incl = clean_version(m.get("versionEndIncluding"))
                fixed = clean_version(m.get("versionEndExcluding"))
                if not max_incl and not fixed and version not in ("*", "-", ""):
                    max_incl = clean_version(version)
                found.append((slug, max_incl, fixed))
    return found


def from_refs(cve, text):
    kinds = []
    for ref in cve.get("references", []) or []:
        url = ref.get("url", "")
        for kind, rx in REF_PATTERNS:
            m = rx.search(url)
            if m:
                slug = m.group(1).lower()
                if slug not in NOT_SLUGS and SLUG_RE.match(slug):
                    kinds.append((kind, slug))
    # o slug mais frequente nas referências
    if not kinds:
        return None
    best = max(set(kinds), key=kinds.count)
    return best


def versions_from_text(text):
    for rx in UP_TO_INCL:
        m = rx.search(text)
        if m and clean_version(m.group(1)):
            return clean_version(m.group(1)), ""
    for rx in BEFORE:
        m = rx.search(text)
        if m and clean_version(m.group(1)):
            return "", clean_version(m.group(1))
    return "", ""


def short_title(text):
    t = re.sub(r"\s+", " ", text).strip()
    m = re.search(r"is vulnerable to ([^.]+?)(?: via | in all versions| in versions|\.|$)", t, re.I)
    if m:
        t = m.group(1)
    else:
        m = re.match(r"^(.{5,120}?) vulnerability in ", t, re.I)
        if m:
            t = re.sub(r"\s*\('([^']+)'\)", "", m.group(1))
    t = t[0].upper() + t[1:] if t else t
    return (t[:137] + "...") if len(t) > 140 else t


def analyse(item, kev_ids):
    cve = item.get("cve", item)
    cve_id = cve.get("id", "")
    status = (cve.get("vulnStatus") or "").lower()
    if not cve_id or status in ("rejected",):
        return []
    text = description(cve)
    if "wordpress" not in text.lower() and not cve.get("configurations"):
        return []
    sev, score = severity(cve)
    entries = []

    # Slug: das referências (wordpress.org, trac, patchstack) — o nome do produto na CPE
    # nem sempre é o nome da pasta do plugin. Versões: do texto do aviso; senão da CPE.
    cpe = [c for c in from_cpe(cve) if SLUG_RE.match(c[0])]
    ref = from_refs(cve, text)
    t_max, t_fixed = versions_from_text(text)
    if ref:
        kind, slug = ref
        max_incl, fixed = t_max, t_fixed
        if not (max_incl or fixed) and cpe:
            max_incl, fixed = cpe[0][1], cpe[0][2]
        if max_incl or fixed:
            entries.append((kind, slug, max_incl, fixed))
    elif cpe and re.search(r"plugin|theme|tema", text, re.I):
        # Só com a CPE: exige que o aviso fale de um plugin ou tema (evita produtos como painéis de alojamento).
        kind = kind_from_text(text)
        for slug, max_incl, fixed in cpe:
            if t_max or t_fixed:
                max_incl, fixed = t_max, t_fixed
            if max_incl or fixed:
                entries.append((kind, slug, max_incl, fixed))

    out = []
    for kind, slug, max_incl, fixed in entries:
        e = {
            "type": kind,
            "slug": slug,
            "max_version": max_incl,
            "fixed_in": fixed,
            "severity": sev or "medium",
            "title": short_title(text),
            "cve": cve_id,
            "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            "source": "NVD",
            "published": (cve.get("published") or "")[:10],
        }
        if cve_id in kev_ids:
            e["exploited"] = True
            e["severity"] = "critical"
            e["source"] = "NVD + CISA KEV"
        out.append((e, score))
    return out


# ---------------------------------------------------------------- principal


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14, help="janela de modificações a recolher na NVD")
    ap.add_argument("--min-severity", default="high", choices=list(SEVERITY_RANK), help="gravidade mínima (as exploradas ativamente entram sempre)")
    ap.add_argument("--keep-days", type=int, default=365, help="descartar entradas publicadas há mais de N dias (exceto exploradas)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--from-files", nargs="*", help="respostas NVD gravadas (testes, sem rede)")
    ap.add_argument("--kev", help="ficheiro KEV gravado (testes, sem rede)")
    args = ap.parse_args()

    # 1. CISA KEV (CC0).
    if args.kev:
        kev = json.load(open(args.kev, encoding="utf-8"))
    elif args.from_files is not None:
        kev = {"vulnerabilities": []}
    else:
        print("A descarregar CISA KEV...", file=sys.stderr)
        kev = http_json(KEV_URL)
    kev_all = {v.get("cveID") for v in kev.get("vulnerabilities", [])}
    kev_wp = {
        v.get("cveID") for v in kev.get("vulnerabilities", [])
        if "wordpress" in (str(v.get("vendorProject", "")) + " " + str(v.get("product", "")) + " " + str(v.get("shortDescription", ""))).lower()
    }

    # 2. NVD.
    if args.from_files is not None:
        items = []
        for path in args.from_files:
            items.extend(json.load(open(path, encoding="utf-8")).get("vulnerabilities", []))
    else:
        print(f"A consultar a NVD (últimos {args.days} dias)...", file=sys.stderr)
        items = fetch_nvd(args.days)
        missing = sorted(kev_wp - {i.get("cve", {}).get("id") for i in items})
        if missing:
            print(f"A consultar {len(missing)} CVE do KEV ligados ao WordPress...", file=sys.stderr)
            items.extend(fetch_nvd_ids(missing))

    # 3. Rascunho anterior (acumulado) + novas entradas.
    previous = {}
    patterns = []
    if os.path.exists(args.out):
        prev = json.load(open(args.out, encoding="utf-8"))
        patterns = prev.get("patterns", [])
        for e in prev.get("vulnerabilities", []):
            previous[(e.get("cve"), e.get("type"), e.get("slug"))] = e

    min_rank = SEVERITY_RANK[args.min_severity]
    added = updated = 0
    for item in items:
        for e, _score in analyse(item, kev_all):
            if not e.get("exploited") and SEVERITY_RANK.get(e["severity"], 0) < min_rank:
                continue
            key = (e["cve"], e["type"], e["slug"])
            if key in previous:
                if previous[key] != e:
                    updated += 1
            else:
                added += 1
            previous[key] = e

    cutoff = (dt.date.today() - dt.timedelta(days=args.keep_days)).isoformat()
    vulns = [e for e in previous.values() if e.get("exploited") or not e.get("published") or e["published"] >= cutoff]
    vulns.sort(key=lambda e: (e.get("published", ""), e["cve"]), reverse=True)

    draft = {
        "type": "potamus-definitions",
        "draft": True,
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [
            {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "license": "CC0"},
            {"name": "NVD", "url": "https://nvd.nist.gov", "notice": NVD_NOTICE},
        ],
        "patterns": patterns,
        "vulnerabilities": vulns,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(draft, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"Rascunho: {len(vulns)} vulnerabilidades ({added} novas, {updated} atualizadas) -> {args.out}")


if __name__ == "__main__":
    main()
