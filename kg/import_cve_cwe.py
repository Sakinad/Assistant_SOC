import csv
import io
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone

import requests
from config import get_driver

CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DAYS_BACK = 90          # période importée (modifie si besoin)
WINDOW_DAYS = 30        # NVD limite une requête à 120 jours maximum
PAGE_SIZE = 500
MAX_RETRIES = 6
API_KEY = os.getenv("NVD_API_KEY")          # optionnelle, accélère l'import
PAUSE = 1 if API_KEY else 7                 # secondes entre deux requêtes


def import_cwe(driver):
    print("Téléchargement des CWE...")
    raw = requests.get(CWE_URL, timeout=120).content
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        name = z.namelist()[0]
        text = z.read(name).decode("utf-8-sig")
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        cid = r.get("CWE-ID")
        if cid:
            rows.append({"id": f"CWE-{cid}", "name": r.get("Name", "")})
    with driver.session() as s:
        s.run("UNWIND $rows AS r MERGE (w:Weakness {cwe_id:r.id}) "
              "SET w.name=r.name", rows=rows)
    print(f"{len(rows)} CWE importées.")


def fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_cve(item):
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if cve.get("metrics", {}).get(key):
            cvss = cve["metrics"][key][0]["cvssData"]["baseScore"]
            break
    cwes = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):          # ignore NVD-CWE-Other / noinfo
                cwes.add(v)
    return {"id": cve["id"], "desc": desc, "cvss": cvss, "cwes": sorted(cwes)}


def fetch_window(start, end):
    cves, index = [], 0
    headers = {"apiKey": API_KEY} if API_KEY else {}
    while True:
        params = {"pubStartDate": fmt(start), "pubEndDate": fmt(end),
                  "resultsPerPage": PAGE_SIZE, "startIndex": index}
        data = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.get(NVD_URL, params=params, headers=headers,
                                    timeout=60)
                if resp.status_code == 200:
                    data = resp.json()
                    break
                print(f"  NVD a répondu {resp.status_code} "
                      f"(essai {attempt}/{MAX_RETRIES}), attente 30 s")
            except requests.exceptions.RequestException as e:
                print(f"  Erreur réseau ({type(e).__name__}) "
                      f"(essai {attempt}/{MAX_RETRIES}), attente 30 s")
            time.sleep(30)
        if data is None:
            print("  Fenêtre abandonnée après plusieurs échecs, on continue.")
            return cves
        cves += [parse_cve(v) for v in data.get("vulnerabilities", [])]
        index += data.get("resultsPerPage", 0)
        if index >= data.get("totalResults", 0) or data.get("resultsPerPage", 0) == 0:
            return cves
        time.sleep(PAUSE)


def import_cve(driver):
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=DAYS_BACK)
    total = 0
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=WINDOW_DAYS), end)
        print(f"CVE publiées du {cur.date()} au {nxt.date()}...")
        cves = fetch_window(cur, nxt)
        links = [{"id": c["id"], "cwe": w} for c in cves for w in c["cwes"]]
        with driver.session() as s:
            s.run("UNWIND $rows AS r MERGE (v:Vulnerability {cve_id:r.id}) "
                  "SET v.cvss=r.cvss, v.description=r.desc", rows=cves)
            s.run("UNWIND $rows AS r "
                  "MATCH (v:Vulnerability {cve_id:r.id}) "
                  "MERGE (w:Weakness {cwe_id:r.cwe}) "
                  "MERGE (v)-[:CAUSED_BY]->(w)", rows=links)
        total += len(cves)
        print(f"  {len(cves)} CVE importées.")
        cur = nxt
        time.sleep(PAUSE)
    return total


if __name__ == "__main__":
    driver = get_driver()
    import_cwe(driver)
    n = import_cve(driver)
    with driver.session() as s:
        v = s.run("MATCH (v:Vulnerability) RETURN count(v) AS c").single()["c"]
        w = s.run("MATCH (w:Weakness) RETURN count(w) AS c").single()["c"]
        r = s.run("MATCH ()-[r:CAUSED_BY]->() RETURN count(r) AS c").single()["c"]
    driver.close()
    print(f"Lu dans NVD : {n} CVE.")
    print(f"Dans Neo4j : {v} Vulnerability, {w} Weakness, {r} relations CAUSED_BY.")