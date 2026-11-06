"""Adapters for locally installed tools. No shell, repository configuration, builds, or network."""
import hashlib
import json
import re
from pathlib import Path
from .config import ROOT, settings

RULE_DIR = ROOT / "backend/rules"


def base(engine, path, rule, title, message, severity="medium", category="sast", **extra):
    return {"engine":engine,"path":path,"rule_id":rule,"title":title,"message":message,"severity":severity if severity in {"critical","high","medium","low","info"} else "info","category":category,"confidence":"medium","line":1,"end_line":1,"cwe":"Unmapped","owasp":"Unmapped","classification":"verified_analyzer",**extra}


def gitleaks(directory, run):
    code, raw = run(["gitleaks","dir",str(directory),"--config",str(RULE_DIR/"gitleaks.toml"),"--gitleaks-ignore-path",str(RULE_DIR/"empty.ignore"),"--ignore-gitleaks-allow","--no-banner","--no-color","--log-level","error","--max-decode-depth","0","--max-archive-depth","0","--timeout","90","--report-format","json","--report-path","-","--redact=0"],directory,100)
    if code not in (0,1): raise RuntimeError("Gitleaks failed")
    payload=json.loads(raw or "[]")
    findings, values=[],[]
    for row in payload:
        secret=row.get("Secret","")
        if secret: values.append(secret)
        findings.append(base("Gitleaks",row["File"],row["RuleID"],"Potential exposed credential", "A credential pattern was reported. The value is redacted; verify ownership and revoke it if active.","high","secret",line=row["StartLine"],end_line=row["EndLine"],cwe="CWE-798",owasp="A07:2021 – Identification and Authentication Failures",classification="potential_vulnerability"))
    return findings, values


def osv(directory, run):
    cfg=settings()
    cache=Path(cfg.scanner_cache)
    if not cfg.scanner_cache: raise RuntimeError("OSV cache not configured")
    code,raw=run(["osv-scanner","scan","source","--offline","--no-resolve","--no-call-analysis=all","--no-ignore","--allow-no-lockfiles","--config",str(RULE_DIR/"osv-scanner.toml"),"--format","json","--verbosity","error","-r",str(directory)],directory,180)
    if code not in (0,1): raise RuntimeError("OSV scanner failed")
    payload=json.loads(raw)
    findings=[]
    for result in payload.get("results",[]):
        path=result["source"]["path"]
        for package in result.get("packages",[]):
            info=package["package"]
            for vuln in package.get("vulnerabilities",[]):
                aliases=[vuln["id"],*vuln.get("aliases",[])]
                cve=next((a for a in aliases if a.startswith("CVE-")),vuln["id"])
                fixes=[]
                for affected in vuln.get("affected",[]):
                    if affected.get("package",{}).get("name") != info["name"]: continue
                    fixes.extend(e["fixed"] for r in affected.get("ranges",[]) for e in r.get("events",[]) if "fixed" in e)
                severity=(vuln.get("database_specific",{}).get("severity") or "info").lower()
                if severity=="moderate":severity="medium"
                title=vuln.get("summary") or f"{info['name']} matches {vuln['id']}"
                findings.append(base("OSV-Scanner",path,cve,title[:250],(vuln.get("summary") or "Installed dependency version matches a published advisory. Confirm applicability and reachable code paths.")[:3000],severity,"dependency",package=info["name"],installed_version=info.get("version",""),ecosystem=info.get("ecosystem",""),fixed_version=", ".join(sorted(set(fixes))),advisory_ids=aliases,references=[r["url"] for r in vuln.get("references",[]) if r.get("url","").startswith("https://")][:12],published=vuln.get("published"),modified=vuln.get("modified"),confidence="high",owasp="A06:2021 – Vulnerable and Outdated Components"))
    return findings, []


def trivy(directory, run):
    cfg=settings()
    if not cfg.scanner_cache: raise RuntimeError("Trivy cache not configured")
    code,raw=run(["trivy","--config",str(RULE_DIR/"trivy.yaml"),"--cache-dir",str(Path(cfg.scanner_cache)/"trivy"),"--quiet","--timeout","180s","fs","--scanners","vuln,misconfig","--skip-db-update","--skip-java-db-update","--skip-check-update","--offline-scan","--disable-telemetry","--skip-version-check","--ignorefile",str(RULE_DIR/"empty.ignore"),"--secret-config","","--misconfig-scanners","dockerfile,kubernetes,terraform,cloudformation","--parallel","1","--format","json",str(directory)],directory,190)
    if code != 0:raise RuntimeError("Trivy failed")
    payload=json.loads(raw)
    findings=[]
    for result in payload.get("Results",[]):
        path=result["Target"]
        # Dependency targets may append a package type in human-readable output.
        path=re.sub(r" \([^)]*\)$","",path)
        for v in result.get("Vulnerabilities") or []:
            findings.append(base("Trivy",path,v["VulnerabilityID"],v.get("Title") or v["VulnerabilityID"],(v.get("Description") or "Installed package matches a vulnerability advisory.")[:3000],v.get("Severity","UNKNOWN").lower(),"dependency",package=v["PkgName"],ecosystem=result.get("Type",""),installed_version=v.get("InstalledVersion",""),fixed_version=v.get("FixedVersion",""),advisory_ids=[v["VulnerabilityID"]],references=[u for u in v.get("References",[]) if u.startswith("https://")][:12],cwe=(v.get("CweIDs") or ["Unmapped"])[0],owasp="A06:2021 – Vulnerable and Outdated Components",confidence="high",published=v.get("PublishedDate"),modified=v.get("LastModifiedDate")))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") not in {None,"FAIL"}:continue
            cause=m.get("CauseMetadata") or {}
            findings.append(base("Trivy",path,m.get("AVDID") or m["ID"],m["Title"],(m.get("Description","")+" "+m.get("Resolution",""))[:3000],m.get("Severity","UNKNOWN").lower(),"configuration",line=max(1,cause.get("StartLine") or 1),end_line=max(1,cause.get("EndLine") or 1),references=[u for u in m.get("References",[]) if u.startswith("https://")][:12],owasp="A05:2021 – Security Misconfiguration"))
    return findings, []


ADAPTERS={"gitleaks":("Gitleaks",gitleaks),"osv":("OSV-Scanner",osv),"trivy":("Trivy",trivy)}
