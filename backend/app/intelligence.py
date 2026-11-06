"""Optional public advisory enrichment. Only validated advisory identifiers leave the worker."""
import re
import time
from datetime import timedelta, timezone
import httpx
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from .config import settings
from .models import VulnerabilityReference, now
from .redaction import redact_tree


def fetch_advisory(identifier: str, source: str, db: Session):
    key=f"{source}:{identifier}"
    cached=db.get(VulnerabilityReference,key)
    if cached and cached.expires_at.replace(tzinfo=timezone.utc)>now():return cached.payload
    cooldown=db.get(VulnerabilityReference,f"{source}:cooldown")
    if cooldown and cooldown.expires_at.replace(tzinfo=timezone.utc)>now():return cooldown.payload
    headers={}
    if source=="osv":
        if not re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+)",identifier):return None
        url="https://api.osv.dev/v1/vulns/"+identifier; params=None
    else:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}",identifier):return None
        url="https://services.nvd.nist.gov/rest/json/cves/2.0";params={"cveId":identifier}
        if settings().nvd_api_key:headers["apiKey"]=settings().nvd_api_key
    for attempt in range(2):
        try:
            with httpx.Client(timeout=6,follow_redirects=False) as client:
                response=client.get(url,params=params,headers=headers)
            if response.status_code in (403,429):
                # Respect throttling across jobs using a shared negative-cache entry.
                value={"status":"rate_limited","source":source}
                expires=now()+timedelta(minutes=10)
                break
            if response.status_code==404:
                value={"status":"not_found","source":source};expires=now()+timedelta(hours=6);break
            if response.status_code>=500 and attempt==0:time.sleep(.2);continue
            if response.status_code!=200 or len(response.content)>1_000_000:return None
            data=response.json()
            if source=="osv":
                if data.get("id")!=identifier and identifier not in data.get("aliases",[]):return None
                value={"id":data["id"],"source":"OSV.dev","description":data.get("summary","")[:3000],"published":data.get("published"),"modified":data.get("modified"),"references":[r['url'] for r in data.get('references',[]) if r.get('url','').startswith('https://')][:8]}
            else:
                entries=data.get("vulnerabilities",[])
                if not entries:return None
                item=entries[0]["cve"]
                if item.get("id")!=identifier:return None
                value={"id":identifier,"source":"NVD","description":next((d['value'] for d in item.get('descriptions',[]) if d.get('lang')=='en'),"")[:3000],"published":item.get("published"),"modified":item.get("lastModified"),"metrics":item.get("metrics",{}),"references":[r['url'] for r in item.get('references',[]) if r.get('url','').startswith('https://')][:8]}
            expires=now()+timedelta(hours=settings().advisory_cache_hours);break
        except (httpx.HTTPError,ValueError,KeyError):
            if attempt==0:continue
            return None
    value=redact_tree(value)
    try:
        with db.begin_nested():
            row=cached or VulnerabilityReference(id=key,payload={},expires_at=expires)
            row.payload,row.expires_at=value,expires
            db.add(row)
            if value.get("status")=="rate_limited":
                cooldown=cooldown or VulnerabilityReference(id=f"{source}:cooldown",payload=value,expires_at=expires)
                cooldown.payload,cooldown.expires_at=value,expires
                db.add(cooldown)
            db.flush()
    except IntegrityError:
        pass  # Another worker populated the shared cache; keep the scan transaction usable.
    return value


def enrich_findings(findings,db):
    # Bound network time independently from the number of source findings.
    deadline=time.monotonic()+25
    results={}; budget=4
    for finding in findings:
        ids=finding.get("advisory_ids",[])
        evidence=[]
        for identifier in ids:
            if not isinstance(identifier,str):continue
            source="nvd" if identifier.startswith("CVE-") else "osv"
            key=(source,identifier)
            if key not in results:
                if budget<=0 or time.monotonic()>deadline:continue
                budget-=1
                try:results[key]=fetch_advisory(identifier,source,db)
                except Exception:results[key]=None
            if results[key]:evidence.append(results[key])
            if len(evidence)>=2:break
        if evidence:finding["intelligence"]=evidence
    return findings
