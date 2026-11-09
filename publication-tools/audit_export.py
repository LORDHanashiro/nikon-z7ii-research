"""Audit every reachable release tree/blob, not just ignore patterns or HEAD."""
from pathlib import Path
import ast, collections, hashlib, json, re, subprocess, sys
from safe_export import SECRET, HOME, ASM_LINE, INLINE_PAIR, BYTE_RUN, DENY_EXT, DROP_KEYS

# Audit concrete home paths without mistaking a regex definition for a username.
# Keep the published sanitizer policy unchanged so replayed history stays stable.
AUDIT_HOME=re.compile(r'/home/\w[^/\s"\'<>`]*|/mnt/[a-z]/Users/[^/\s"\'<>`]+|[A-Z]:\\Users\\[^\\\s"\'<>`]+')

def run(repo,*args,data=None):
    return subprocess.run(['git','-C',str(repo),*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
def audit(repo,kind,report):
    commits=run(repo,'rev-list','--all').decode().splitlines();entries=[];blobs={};problems=[];warnings=[]
    refs=run(repo,'for-each-ref','--format=%(refname)').decode().splitlines()
    allowed={'refs/heads/main','refs/heads/research-history'} if kind=='private' else {'refs/heads/main'}
    allowed |= {'refs/remotes/origin/'+r.rsplit('/',1)[1] for r in list(allowed)}
    for ref in refs:
        if ref=='refs/remotes/origin/HEAD':
            target=run(repo,'symbolic-ref',ref).decode().strip()
            if target not in allowed:problems.append({'type':'unexpected-origin-HEAD','ref':ref})
        elif ref not in allowed:problems.append({'type':'unexpected-ref','ref':ref})
    for c in commits:
        obj=run(repo,'cat-file','-p',c).decode()
        if SECRET.search(obj) or AUDIT_HOME.search(obj):problems.append({'type':'commit-metadata-sensitive-pattern','commit':c})
        for item in run(repo,'ls-tree','-r','-z',c).split(b'\0'):
            if not item:continue
            left,p=item.split(b'\t',1);mode,t,oid=left.decode().split();path=p.decode();entries.append((c,path,oid))
            if mode not in ('100644','100755') or t!='blob':problems.append({'type':'unreviewed-mode','path':path})
            if Path(path).suffix.lower() in DENY_EXT or path.startswith(('.github/workflows/','firmware/','src/','logs/','.cache/','research/artifacts/')):problems.append({'type':'forbidden-path','path':path})
            blobs.setdefault(oid,path)
    proc=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    total=0;reference_disabled=set()
    for oid,path in blobs.items():
        proc.stdin.write((oid+'\n').encode());proc.stdin.flush();h=proc.stdout.readline().split();n=int(h[2]);b=proc.stdout.read(n);assert proc.stdout.read(1)==b'\n';total+=n
        if n>2_000_000 or b'\0' in b:problems.append({'type':'binary-or-large','path':path,'blob':oid});continue
        try:s=b.decode()
        except UnicodeDecodeError:problems.append({'type':'nonutf8','path':path});continue
        for name,pat in [('credential',SECRET),('personal-absolute-path',AUDIT_HOME)]:
            if pat.search(s):problems.append({'type':name,'path':path,'blob':oid})
        if any(ASM_LINE.search(l) for l in s.splitlines()):problems.append({'type':'instruction-byte-listing','path':path,'blob':oid})
        if BYTE_RUN.search(s):problems.append({'type':'spaced-byte-excerpt','path':path,'blob':oid})
        if path.endswith('.md'):
            for m in re.finditer(r'`([0-9a-fA-F]{4,32})`',s):
                v=m.group(1)
                if len(v)==8 and re.match(r'(?i)^(?:10|11|12|08|20|24|b1|b2|50)',v):continue
                problems.append({'type':'inline-reference-indicator','path':path,'blob':oid});break
        if re.search(r'(?<![0-9a-fA-F])[0-9a-fA-F]{96,}(?![0-9a-fA-F])',s):problems.append({'type':'long-reference-hex','path':path,'blob':oid})
        if path.endswith('.json'):
            try:j=json.loads(s)
            except json.JSONDecodeError:problems.append({'type':'invalid-json','path':path});continue
            def check(x):
                if isinstance(x,dict):
                    for k,v in x.items():
                        if (k.lower() in DROP_KEYS or k.lower().endswith('_hex')) and isinstance(v,str) and re.fullmatch('[0-9a-fA-F]{2,}',v):problems.append({'type':'firmware-byte-field','path':path,'blob':oid,'key':k})
                        check(v)
                elif isinstance(x,list):
                    for v in x:check(v)
            check(j)
        if path.endswith('.py'):
            try:tree=ast.parse(s)
            except SyntaxError:problems.append({'type':'invalid-python','path':path});continue
            for node in tree.body:
                if isinstance(node,ast.Raise) and isinstance(node.exc,ast.Call) and isinstance(node.exc.func,ast.Name) and node.exc.func.id=='RuntimeError' and any(isinstance(a,ast.Constant) and isinstance(a.value,str) and a.value.startswith('Sanitized historical source: restore local firmware reference') for a in node.exc.args):
                    reference_disabled.add(path)
            if path.startswith(('tools/research/','tools/phase')):
                for node in ast.walk(tree):
                    if isinstance(node,ast.Constant) and isinstance(node.value,str) and re.fullmatch('[0-9a-fA-F]{4,128}',node.value) and len(node.value)%2==0 and len(node.value) not in (40,64):
                        problems.append({'type':'unremoved-reference-literal','path':path,'blob':oid,'line':node.lineno});break
    proc.stdin.close();assert proc.wait()==0
    result=dict(repository_kind=kind,scope='Every tree and reachable commit/blob under all local refs',commits_checked=len(commits),unique_blobs_checked=len(blobs),historical_tree_entries_checked=len(entries),reachable_text_bytes=total,refs=refs,reference_dependent_paths_disabled=len(reference_disabled),problems=problems,passed=not problems,limitations=['Pattern/category audit is not a legal opinion or universal secret detector.','Original raw evidence and databases remain local; source digests are not uploaded source data.','No legal right to redistribute Nikon firmware is granted.','No camera/hardware/10bit capability validation performed by this audit.'])
    report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('problems','limitations')},indent=2))
    if problems:print(json.dumps(problems[:20],indent=2));return False
    return True

if __name__=='__main__':
    ok=audit(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]));raise SystemExit(0 if ok else 1)
