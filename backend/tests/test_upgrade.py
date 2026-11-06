import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from datetime import timedelta
from sqlmodel import Session
from app.config import ROOT, settings
from app.main import app
from app.models import get_db, VulnerabilityReference, now


def test_preferences_response_persists_both_fields(authenticated):
    response=authenticated.patch('/preferences',json={'notify_scan_failure':False,'notify_high_findings':True})
    assert response.status_code==200
    assert response.json()=={'notify_scan_failure':False,'notify_high_findings':True}
    assert authenticated.get('/preferences').json()==response.json()


def test_advisory_rate_limit_is_shared_and_never_receives_source(authenticated,monkeypatch):
    import httpx
    from app.intelligence import fetch_advisory
    calls=[]
    class Client:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,url,params=None,headers=None):
            calls.append((url,params))
            return httpx.Response(429)
    monkeypatch.setattr('app.intelligence.httpx.Client',Client)
    with next(app.dependency_overrides[get_db]()) as db:
        assert fetch_advisory('CVE-2020-12345','nvd',db)['status']=='rate_limited'
        assert fetch_advisory('CVE-2020-22222','nvd',db)['status']=='rate_limited'
        assert len(calls)==1
        assert calls[0][0]=='https://services.nvd.nist.gov/rest/json/cves/2.0'
        assert calls[0][1]=={'cveId':'CVE-2020-12345'}
        assert fetch_advisory('../../evil','osv',db) is None
        db.commit()


def test_migration_preserves_real_evidence_and_removes_fixture(tmp_path):
    database=tmp_path/'migration.db'
    env={**os.environ,'DATABASE_URL':f'sqlite:///{database}'}
    command=[sys.executable,'-m','alembic','-c',str(ROOT/'backend/alembic.ini'),'upgrade']
    subprocess.run([*command,'001'],cwd=ROOT,env=env,check=True,capture_output=True)
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO user(id,github_id,login,encrypted_token) VALUES(?,?,?,?)',('user',123,'owner',''))
        for name,fixture in [('real',False),('fixture',True)]:
            db.execute('INSERT INTO repository(id,owner_id,full_name,branch,is_fixture,created_at) VALUES(?,?,?,?,?,?)',(name,'user',f'owner/{name}','main',fixture,'2026-01-01'))
            finding={'fingerprint':'stable','severity':'high','title':'Existing evidence','path':'app.py','line':1,'engine':'Bandit','rule_id':'B602'}
            db.execute('INSERT INTO scan(id,repository_id,commit_sha,status,created_at,findings,files,coverage) VALUES(?,?,?,?,?,?,?,?)',(name,name,'a'*40,'completed','2026-01-01',json.dumps([finding]),json.dumps({'app.py':'old retained source'}),'{"complete":true}'))
        db.commit()
    subprocess.run([*command,'head'],cwd=ROOT,env=env,check=True,capture_output=True)
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT id FROM repository').fetchall()==[('real',)]
        assert db.execute('SELECT fingerprint,status FROM findingrecord').fetchall()==[('stable','open')]
        assert json.loads(db.execute('SELECT files FROM scan').fetchone()[0])=={}
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()[0]=='002'
