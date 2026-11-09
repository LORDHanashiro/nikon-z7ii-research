"""Separate, repeatable local preparation and explicitly gated GitHub pushes."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, shutil, subprocess, sys

BUNDLE=Path(__file__).resolve().parent
IDENT=['-c','user.name=Nikon Research Agent','-c','user.email=agent@localhost']
MANAGER_FILES=('safe_export.py','audit_export.py','build_public.py','sync.py')

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def call(argv,cwd=None,env=None,check=True):
    return subprocess.run(argv,cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check)
def git(repo,*args,check=True):return call(['git','-C',str(repo),*args],check=check)
def dump(p,obj):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def bundle(repo):
    out=repo/'publication-tools';out.mkdir(exist_ok=True)
    for n in MANAGER_FILES:shutil.copyfile(BUNDLE/n,out/n)
    for p in (BUNDLE/'templates').rglob('*'):
        if p.is_file():
            q=out/'templates'/p.relative_to(BUNDLE/'templates');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)

def files(repo):
    result=[]
    for p in repo.rglob('*'):
        if not p.is_file():continue
        rel=p.relative_to(repo)
        if any(x in ('.git','__pycache__','.cache','build') for x in rel.parts) or p.suffix=='.pyc':continue
        result.append(p)
    return sorted(result)

def seal(repo,kind):
    controls={'review-manifest.json','SHA256SUMS'}
    if kind=='public':
        names={str(p.relative_to(repo)) for p in files(repo)}|controls|{'PUBLIC-FILES.txt'}
        (repo/'PUBLIC-FILES.txt').write_text('\n'.join(sorted(names))+'\n')
    payload=[p for p in files(repo) if str(p.relative_to(repo)) not in controls]
    manifest=dict(schema=1,repository_kind=kind,scope='Screened publication payload; control files listed separately to avoid self-hash recursion',members=[dict(path=str(p.relative_to(repo)),bytes=p.stat().st_size,sha256=sha(p)) for p in payload],control_files=sorted(controls),safety='No firmware/decrypted images/keys/captures/databases. Metadata and tests do not establish camera recording.')
    dump(repo/'review-manifest.json',manifest)
    checks=[p for p in files(repo) if p.name!='SHA256SUMS']
    (repo/'SHA256SUMS').write_text(''.join(sha(p)+'  '+str(p.relative_to(repo))+'\n' for p in checks))
    verify(repo)
    return sha(repo/'review-manifest.json')

def verify(repo):
    m=json.loads((repo/'review-manifest.json').read_text())
    listed={x['path'] for x in m['members']}|set(m['control_files'])
    actual={str(p.relative_to(repo)) for p in files(repo)}
    assert listed==actual,'Manifest membership mismatch'
    for x in m['members']:
        p=repo/x['path'];assert p.stat().st_size==x['bytes'] and sha(p)==x['sha256'],x['path']
    checks={}
    for line in (repo/'SHA256SUMS').read_text().splitlines():
        h,p=line.split('  ',1);assert sha(repo/p)==h,p;checks[p]=h
    assert set(checks)==actual-{'SHA256SUMS'}

def finish_public(repo):
    bundle(repo)
    (repo/'AUDIT.md').write_text('''# Publication review boundary

This candidate is built from a fixed allowlist of self-authored descriptive findings, metadata indices and host-only tools. Original byte guards, original disassembly/decompilation, firmware, keys, captures, personal paths, databases and third-party implementations are not included.

Required gates: complete reachable Git-history audit; manifest/SHA256SUMS membership verification; finite host tests; no private-history parents or refs; and explicit owner confirmation before the first public push. The push helper never starts authentication and refuses a public push without the current manifest digest.

Packaging found an EX source index with relations but no node table. Explicit UNKNOWN endpoints with blank addresses preserve those relations without inventing function addresses or raising evidence grades. The initial failed test and correction are retained locally. No test was removed or skipped.

The audit is a scoped content/rights review, not a legal opinion or proof of camera capability. Source bytes are intentionally withheld, limiting independent public instruction-level reproduction. No blanket license for original material is granted by publication.
''')
    seal(repo,'public')

def finish_private(repo,source,work):
    from safe_export import safe_json,safe_text
    export=json.loads((work/'private-history-export.json').read_text())
    previous_local=json.loads((repo/'EXCLUDED-LOCAL.json').read_text()) if (repo/'EXCLUDED-LOCAL.json').is_file() else {}
    dump(repo/'SOURCE-HISTORY.json',export)
    summary=dict(official_inputs=[],persistent_analysis_projects=[],raw_logs=dict(location='<WORKSPACE>/logs',files=sum(1 for p in (source/'logs').rglob('*') if p.is_file()),content='LOCAL ONLY; command receipts and hashes are backed up, raw outputs are not copied'),excluded_categories=['Original firmware and decrypted modules','Recovery tables, keys and authentication material','Private captures and RAM/NVRAM/device identity data','Third-party checkouts/vendor distributions','Ghidra databases and binary/build artifacts','Original instruction/byte/decompilation excerpts and uncertain third-party quotations'])
    allowed=('Z7_2_0170.bin','Z_6_0380.bin','Z_50_0260.bin','Z_8_0312.bin')
    inputs=[source/'firmware/originals'/n for n in allowed]+sorted((source/'firmware/extracted').glob('*.payload.bin'))
    for p in inputs:
        if p.is_file():summary['official_inputs'].append(dict(path='<WORKSPACE>/'+str(p.relative_to(source)),bytes=p.stat().st_size,sha256=sha(p),content='LOCAL ONLY'))
    roots=['research/artifacts/ghidra/nikon-system-map.gpr','research/artifacts/ghidra/nikon-system-map.rep','research/artifacts/ghidra/nikon-sla-map.gpr','research/artifacts/ghidra/nikon-sla-map.rep','research/artifacts/ghidra/ex-persistent/ex-origin.gpr','research/artifacts/ghidra/ex-persistent/ex-origin.rep']
    for name in roots:
        root=source/name
        ps=[root] if root.is_file() else sorted(root.rglob('*')) if root.is_dir() else []
        for p in ps:
            if p.is_file() and not p.name.endswith('.lock'):
                before=p.stat();h=sha(p);after=p.stat();assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Analysis file changed during snapshot'
                summary['persistent_analysis_projects'].append(dict(path='<WORKSPACE>/'+str(p.relative_to(source)),bytes=p.stat().st_size,sha256=h,content='LOCAL ONLY'))
    if previous_local.get('original_git_bundle'):
        summary['original_git_bundle']=previous_local['original_git_bundle']
    dump(repo/'EXCLUDED-LOCAL.json',summary)
    bundles=sorted((work/'local-only').glob('original-research-*.bundle'))
    if bundles:
        summary['original_git_bundle']=[dict(location='<WORKSPACE>/'+str(p.relative_to(source)),bytes=p.stat().st_size,sha256=sha(p),content='LOCAL ONLY; original unscreened history must never be pushed') for p in bundles if p.is_relative_to(source)]
        dump(repo/'EXCLUDED-LOCAL.json',summary)
    receipts=[]
    for p in sorted((source/'research/experiments').glob('*/record.json')):
        j=json.loads(p.read_text())
        for c in j.get('commands',[]):receipts.append(dict(experiment=j['id'],receipt=safe_json(c)))
    (repo/'COMMAND-RECEIPTS.jsonl').write_text(''.join(json.dumps(v,ensure_ascii=False)+'\n' for v in receipts))
    (repo/'README.md').write_text(f'''# Nikon Z7 II screened private research backup

This is an independently screened backup, not the original research Git repository and not a working firmware implementation. Genuine 10-bit N-Log internal recording has NOT been implemented; encoder 10-bit support remains UNKNOWN.

The research-history branch preserves {export['source_commits']} logical source commits with screened contents, original ordering/times and a non-person author identity. Original commit IDs necessarily change. main adds backup manifests and synchronization tools. No original Git objects were fetched or mirrored. The source history remains untouched.

Byte fields, long original instruction excerpts, private paths and quotations were removed. Reference-dependent historical Python scripts explicitly fail before execution; other reference-dependent source is non-executable text under redacted-sources. This avoids pretending that weakened checks pass. Do not treat the screened tree as a bit-identical or fully runnable restore of original raw evidence.

See SOURCE-HISTORY.json for commit mapping/transformation provenance, EXCLUDED-LOCAL.json for local-only input/database integrity, COMMAND-RECEIPTS.jsonl for screened execution metadata, RESTORE.md, AUDIT.md and publication-tools/sync.py. Historical states/permissions in old notes are historical evidence, not instructions to resume research or camera operations.
''')
    (repo/'RESTORE.md').write_text('''# Restore boundaries

Clone the private repository and inspect SOURCE-HISTORY.json. The research-history branch contains screened historical research files; main adds backup control files. SHA256SUMS and review-manifest.json describe the screened current payload. Older research manifests/hashes refer to local original evidence, not necessarily these redacted copies.

Original firmware, extracted modules, keys, private captures, raw logs, binaries and complete Ghidra projects were not uploaded. Recover them only from independently maintained local storage; verify the permitted input/database hashes in EXCLUDED-LOCAL.json. Keys/device-private captures are intentionally not enumerated. Third-party projects must be obtained independently at their pinned revisions under their own licenses.

For exact historical source, use the untouched original local repository or the local-only original Git bundle retained by the publisher. Redacted reference literals cannot be reconstructed from this GitHub backup alone. Do not run disabled reference-dependent scripts or infer a passing firmware test from sanitization. Safe host-only tools remain separate.

To recover analysis metadata without large databases, use the public metadata recipe in a fresh local project with lawfully obtained matching components. No script invents RAM content or a hardware completion event.
''')
    (repo/'AUDIT.md').write_text('''# Private backup audit policy

Every proposed reachable commit/tree/blob must be screened, including historical versions and metadata. This backup never fetches original repository objects. Fixed binary/sensitive paths, keys, private captures and vendor code are excluded; original byte fields and excerpts are redacted; personal absolute paths are normalized. Original authors are replaced with a non-person identity. Local manifests contain locations, sizes and hashes, not excluded content.

Raw logs remain local. Their screened command receipts and research records preserve status, errors, provenance and output digests. Full Ghidra databases remain local with per-file integrity metadata. This is a screened historical backup, not complete off-machine disaster recovery of all raw evidence.

The initial content rules missed inline reference words and a spaced image-header excerpt. Manual review found them; a stricter sanitizer and independent audit were run on a fresh independent history. The superseded candidate was never uploaded. Reports remain in the local publication work directory.

This scoped review is not a legal opinion or universal secret detector. No rights in Nikon proprietary material are granted. No third-party implementation or vendor distribution is included. Historical source code with removed reference literals is explicitly disabled rather than made to pass.
''')
    bundle(repo)
    seal(repo,'private')

def staged_record(repo,work):
    git(repo,'add','--all')
    (work/'staged-paths.txt').write_text(git(repo,'diff','--cached','--name-status').stdout)
    (work/'staged-diff.txt').write_text(git(repo,'diff','--cached','--no-ext-diff').stdout)
    git(repo,'diff','--cached','--check')

def commit(repo,message):
    if git(repo,'diff','--cached','--quiet',check=False).returncode:
        git(repo,*IDENT,'commit','-m',message)

def push(repo,kind,owner,gh,approval,work):
    from audit_export import audit
    verify(repo)
    if git(repo,'status','--porcelain').stdout.strip():raise RuntimeError('Refuse to push dirty/untracked content')
    if kind=='public' and approval!=sha(repo/'review-manifest.json'):raise RuntimeError('Public push requires explicit operator approval of current manifest SHA-256')
    if not audit(repo,kind,work/(kind+'-prepush-audit.json')):raise RuntimeError('History audit failed')
    login=call([gh,'api','user','--jq','.login']).stdout.strip()
    if login!=owner:raise RuntimeError('Owner differs from selected GitHub CLI account; no automatic organization/account switch')
    name='nikon-z7ii-research-backup' if kind=='private' else 'nikon-z7ii-research'
    full=owner+'/'+name
    r=call([gh,'api','repos/'+full],check=False)
    if r.returncode:
        if '404' not in r.stderr:raise RuntimeError('GitHub authentication/access/network failed; no repository mutation')
        call([gh,'repo','create',full,'--'+('private' if kind=='private' else 'public'),'--disable-wiki'])
        r=call([gh,'api','repos/'+full])
    meta=json.loads(r.stdout)
    if meta['private']!=(kind=='private'):raise RuntimeError('Remote visibility mismatch; never change it or push automatically')
    branch=call([gh,'api','repos/'+full+'/git/ref/heads/main','--jq','.object.sha'],check=False)
    if branch.returncode==0:
        old=branch.stdout.strip()
        if git(repo,'merge-base','--is-ancestor',old,'main',check=False).returncode:raise RuntimeError('Existing remote history is not a local safe ancestor; no force push')
    elif '404' not in branch.stderr:raise RuntimeError('Cannot verify remote main state')
    else:
        branches=json.loads(call([gh,'api','repos/'+full+'/branches']).stdout)
        if branches:raise RuntimeError('Existing repository has other history but no verified main; refuse initial push')
    url='https://github.com/'+full+'.git'
    remotes=git(repo,'remote').stdout.splitlines()
    if 'origin' in remotes:
        if git(repo,'remote','get-url','origin').stdout.strip()!=url:raise RuntimeError('Unexpected origin; never retarget automatically')
    else:git(repo,'remote','add','origin',url)
    import shlex
    refs=['refs/heads/main:refs/heads/main']
    if kind=='private':refs.append('refs/heads/research-history:refs/heads/research-history')
    helper='!'+shlex.quote(str(Path(gh).resolve()))+' auth git-credential'
    git(repo,'-c','credential.helper=','-c','credential.helper='+helper,'push','--atomic','origin',*refs)
    remote=call([gh,'api','repos/'+full+'/git/ref/heads/main','--jq','.object.sha']).stdout.strip()
    assert remote==git(repo,'rev-parse','main').stdout.strip()
    meta=json.loads(call([gh,'api','repos/'+full]).stdout);assert meta['private']==(kind=='private')
    dump(work/(kind+'-remote-receipt.json'),dict(url=meta['html_url'],private=meta['private'],main=remote,public_approval_manifest=approval if kind=='public' else None))
    print(json.dumps(dict(url=meta['html_url'],private=meta['private'],main=remote)))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('target',choices=['private','public']);p.add_argument('--source',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--workdir',type=Path,required=True);p.add_argument('--prepare-only',action='store_true');p.add_argument('--push',action='store_true');p.add_argument('--owner');p.add_argument('--gh',default='gh');p.add_argument('--approved-manifest-sha256');a=p.parse_args()
    source=a.source.resolve();repo=a.destination.resolve();work=a.workdir.resolve();work.mkdir(parents=True,exist_ok=True)
    assert source!=repo and not source.is_relative_to(repo),'Destination cannot be the source or its ancestor'
    if repo.is_relative_to(source):assert repo.is_relative_to(source/'research/artifacts'),'Use an ignored independent destination'
    assert source!=work and not source.is_relative_to(work),'Work directory cannot overwrite source'
    if work.is_relative_to(source):assert work.is_relative_to(source/'research/artifacts') or work.is_relative_to(source/'.cache'),'Use ignored local work directory'
    os.environ.update(NIKON_RESEARCH_ROOT=str(source),NIKON_PUBLICATION_WORKDIR=str(work),NIKON_PRIVATE_DESTINATION=str(repo),NIKON_PUBLIC_DESTINATION=str(repo))
    if a.push:
        if not a.owner:raise SystemExit('--owner required for push')
        push(repo,a.target,a.owner,a.gh,a.approved_manifest_sha256,work);return
    if a.target=='private':
        from safe_export import build_history
        build_history();finish_private(repo,source,work)
    else:
        if (repo/'.git').exists():
            if git(repo,'status','--porcelain').stdout.strip():raise RuntimeError('Destination must be clean before refresh')
            stage=work/('public-candidate-'+datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
            os.environ['NIKON_PUBLIC_DESTINATION']=str(stage)
            import safe_export;safe_export.PUBLIC=stage
            import build_public;build_public.PUBLIC=stage;build_public.build_public();finish_public(stage)
            previous=json.loads((repo/'review-manifest.json').read_text());old={x['path'] for x in previous['members']}|set(previous['control_files']);new={str(x.relative_to(stage)) for x in files(stage)}
            for name in old-new:
                q=repo/name;assert q.resolve().is_relative_to(repo);q.unlink()
            for name in new:
                q=repo/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(stage/name,q)
        else:
            from build_public import build_public
            build_public();finish_public(repo);git(repo,'init','--initial-branch=main')
        test=call([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=repo,check=False)
        (work/'public-unit-tests.log').write_text(test.stdout+test.stderr)
        if test.returncode:raise RuntimeError('Public host tests failed; no commit/push')
    staged_record(repo,work)
    if a.prepare_only:
        print('Prepared/staged locally; inspect staged-paths.txt and staged-diff.txt before commit. No network/authentication attempted.');return
    commit(repo,'Update screened '+a.target+' publication snapshot')
    from audit_export import audit
    if not audit(repo,a.target,work/(a.target+'-history-audit.json')):raise RuntimeError('History audit failed; no push')
    verify(repo);print('Local update audited. No push. Manifest SHA-256: '+sha(repo/'review-manifest.json'))

if __name__=='__main__':main()
