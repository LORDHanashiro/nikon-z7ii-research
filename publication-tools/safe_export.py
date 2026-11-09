"""Screened history export. Never fetch original Git objects into a release repo."""
from pathlib import Path
import ast, collections, datetime, hashlib, io, json, os, re, shutil, subprocess, tokenize

ROOT=Path(os.environ.get('NIKON_RESEARCH_ROOT',str(Path(__file__).resolve().parents[4]))).resolve()
BASE=Path(os.environ.get('NIKON_PUBLICATION_WORKDIR',str(Path(__file__).resolve().parent))).resolve()
PRIVATE=Path(os.environ.get('NIKON_PRIVATE_DESTINATION',str(BASE/'private'))).resolve()
PUBLIC=Path(os.environ.get('NIKON_PUBLIC_DESTINATION',str(BASE/'public'))).resolve()
POLICY='screened-history-v2'
IDENT='Nikon Research Agent <agent@localhost>'
DENY_PREFIX=('firmware/','src/','logs/','downloads/','build/','.cache/','research/artifacts/','notes/upstream/','.github/workflows/')
DENY_EXT={'.bin','.img','.rom','.key','.pem','.p12','.pcap','.pcapng','.gpr','.gz','.zip','.7z','.iso','.mp4','.mov','.nef','.raw','.dng','.bundle','.pack'}
SECRET=re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|\bsk-(?:proj-)?[A-Za-z0-9_-]{24,})')
HOME=re.compile(r'/home/\w[^/\s"\'<>`]*|/mnt/[a-z]/Users/[^/\s"\'<>`]+|[A-Z]:\\Users\\[^\\\s"\'<>`]+')
ASM_LINE=re.compile(r'(?i)^\s*(?:0x)?10[0-9a-f]{6}\s+[0-9a-f]{4,32}\s+')
INLINE_PAIR=re.compile(r'(?i)\b(?:0x)?10[0-9a-f]{6}[\s:`|]+[0-9a-f]{4,32}\b')
BYTE_RUN=re.compile(r'(?i)(?:\b[0-9a-f]{2}[ \t]+){7,}[0-9a-f]{2}\b')
DROP_KEYS={'raw','raw_guard','raw_bytes','original_bytes','head16','footer16','head32','tail32','header16','footer','source_footer','firmware_bytes','disassembly','decompilation','decompiled','instruction','source_before','source_after','stdout','stderr','content','excerpt','snippet','quote','private_key','password','access_token','refresh_token','oauth_token','xor_key','xor_table','key_table','recovered_key','device_serial','serial_number','bodyserialnumber'}
stats=collections.Counter()

def run(argv,**kw):
    return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,**kw).stdout
def git(*a,data=None):return run(['git','-C',str(ROOT),*a],input=data)
def sha(b):return hashlib.sha256(b).hexdigest()
def safe_text(s):
    s=s.replace(str(ROOT),'<WORKSPACE>')
    s=HOME.sub('<USER_HOME>',s)
    s=SECRET.sub('[CREDENTIAL REMOVED]',s)
    s=re.sub(r'(?i)(?:raw_guard|raw bytes?|original bytes?|原始字节)\s*[=:]\s*[`"\']?[0-9a-f]{4,128}', '[local reference removed]',s)
    s=re.sub(r'(?<![0-9a-fA-F])[0-9a-fA-F]{96,}(?![0-9a-fA-F])','[LONG REFERENCE REMOVED]',s)
    s=re.sub(r'(?i)((?:serial(?:_number)?|device_serial|bodyserialnumber)\s*[=:]\s*)["\']?[A-Za-z0-9-]{6,}',r'\1[DEVICE IDENTIFIER REMOVED]',s)
    def inline(m):
        h=m.group(1)
        if len(h)==8 and re.match(r'(?i)^(?:10|11|12|08|20|24|b1|b2|50)',h):return m.group(0)
        return '[local reference removed]'
    s=re.sub(r'`([0-9a-fA-F]{4,32})`',inline,s)
    s=BYTE_RUN.sub('[BYTE EXCERPT REMOVED]',s)
    return s
def safe_json(x):
    if isinstance(x,dict):
        out={}
        for k,v in x.items():
            if k.lower() in DROP_KEYS or k.lower().endswith(('_raw_bytes','_head16','_footer16','_hex')) or (isinstance(v,(list,str)) and any(t in k.lower() for t in ('raw_bytes','header_bytes','sof_bytes'))):
                stats['json_reference_fields_removed']+=1;continue
            out[k]=safe_json(v)
        return out
    if isinstance(x,list):return [safe_json(v) for v in x]
    if isinstance(x,str):return safe_text(x)
    return x

def safe_markdown(s):
    lines=s.splitlines(keepends=True);out=[];i=0
    while i<len(lines):
        line=lines[i]
        if line.lstrip().startswith(('```','~~~')):
            fence=line.lstrip()[:3];lang=line.strip()[3:].lower();j=i+1
            while j<len(lines) and not lines[j].lstrip().startswith(fence):j+=1
            block=''.join(lines[i:j+1]);body=''.join(lines[i+1:j])
            derived=lang in ('asm','assembly','arm','thumb','disassembly','decompiled','pseudocode') or BYTE_RUN.search(body) or any(ASM_LINE.search(q) or INLINE_PAIR.search(q) for q in body.splitlines()) or bool(re.search(r'\b(?:undefined[1248]|FUN_10[0-9a-f]{6}|param_[0-9]+)\b',body))
            if derived:
                out.append('\n[Original instruction/byte excerpt withheld; retain local evidence and descriptive analysis.]\n');stats['markdown_reference_blocks_removed']+=1
            else:out.append(safe_text(block))
            i=j+1;continue
        if line.lstrip().startswith('>'):
            out.append('[Third-party quotation withheld; consult its cited primary source.]\n');stats['quotations_removed']+=1
        elif ASM_LINE.search(line) or INLINE_PAIR.search(line):
            out.append('[Instruction/byte evidence row withheld; see local source evidence.]\n');stats['markdown_reference_rows_removed']+=1
        else:out.append(safe_text(line))
        i+=1
    return ''.join(out)

def safe_code(path,s):
    # Reference-heavy analysis scripts retain algorithms, but never silently run
    # with altered reference data. They fail closed until local originals return.
    fw=path.startswith(('tools/research/','tools/phase3/','tools/phase4/','tools/phase5/','tools/phase6/','tools/phase7/','tools/phase8/','tools/phase2/'))
    changed=False
    if fw:
        if path.endswith('.py'):
            try:
                toks=[]
                for t in tokenize.generate_tokens(io.StringIO(s).readline):
                    if t.type==tokenize.STRING:
                        try:v=ast.literal_eval(t.string)
                        except (ValueError,SyntaxError):v=None
                        keep=True
                        if isinstance(v,str):
                            h=v.strip()
                            if re.fullmatch('[0-9a-fA-F]{4,128}',h) and len(h)%2==0 and len(h) not in (40,64):keep=False
                            line=t.line.lower()
                            if len(h) in (40,64) and re.fullmatch('[0-9a-fA-F]+',h) and ('fromhex' in line or 'raw_guard' in line or 'head16' in line or 'footer16' in line):keep=False
                            if ASM_LINE.search(v) or INLINE_PAIR.search(v):keep=False
                        elif isinstance(v,bytes) and len(v)>=3 and any(c<32 or c>126 for c in v):keep=False
                        if not keep:
                            t=t._replace(string=repr('LOCAL_REFERENCE_REQUIRED'));changed=True;stats['code_reference_literals_removed']+=1
                    toks.append(t)
                s=tokenize.untokenize(toks)
            except (tokenize.TokenError,IndentationError,SyntaxError):
                return None,'unparseable reference-dependent source'
        else:
            def repl(m):
                nonlocal changed
                v=m.group(1)
                if len(v) in (40,64):return m.group(0)
                changed=True;stats['code_reference_literals_removed']+=1
                return '"LOCAL_REFERENCE_REQUIRED"'
            s=re.sub(r'"([0-9a-fA-F]{4,128})"',repl,s)
    s=safe_text(s)
    if changed:
        stats['reference_dependent_code_files']+=1
        if path.endswith('.py'):
            try:
                tree=ast.parse(s);point=0
                for n in tree.body:
                    if isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str):point=n.end_lineno;continue
                    if isinstance(n,ast.ImportFrom) and n.module=='__future__':point=n.end_lineno;continue
                    break
                lines=s.splitlines(keepends=True)
                lines.insert(point,'\nraise RuntimeError("Sanitized historical source: restore local firmware reference literals before execution; no checks were bypassed.")\n')
                s=''.join(lines);ast.parse(s)
            except SyntaxError:return None,'reference redaction cannot preserve Python syntax'
        else:
            # Keep source as non-executable historical text rather than inventing
            # a safe substitute for an original reference-dependent program.
            return ('[NON-EXECUTABLE SANITIZED HISTORICAL SOURCE]\n'+s).encode(),'reference-dependent non-Python source'
    return s.encode(),None

def transform(path,data):
    if path.startswith(DENY_PREFIX) or Path(path).suffix.lower() in DENY_EXT or Path(path).name.startswith('.env'):
        return None,'denied data/source/binary path'
    if len(data)>2_000_000 or b'\0' in data:return None,'large or non-text blob'
    try:s=data.decode('utf-8')
    except UnicodeDecodeError:return None,'non-UTF8 blob'
    if SECRET.search(s):return None,'credential pattern quarantined'
    if re.search(r'(?i)(?:0x[0-9a-f]{96,}|-----BEGIN .*PRIVATE KEY-----)',s):return None,'large embedded key/reference constant'
    if path.endswith('.json'):
        try:return (json.dumps(safe_json(json.loads(s)),ensure_ascii=False,indent=2)+'\n').encode(),None
        except json.JSONDecodeError:return None,'invalid structured evidence'
    if path.endswith('.md'):return safe_markdown(s).encode(),None
    if path.endswith(('.py','.java','.cpp','.c','.h','.sh')):return safe_code(path,s)
    return safe_text(s).encode(),None

def load_objects():
    commits=git('rev-list','--reverse','--topo-order','--all').decode().splitlines()
    trees={};oids=set()
    for c in commits:
        entries=[]
        for line in git('ls-tree','-r','-z',c).split(b'\0'):
            if not line:continue
            left,p=line.split(b'\t',1);mode,kind,oid=left.decode().split()
            if mode!='100644' or kind!='blob':raise RuntimeError('Unreviewed tree entry mode: '+mode)
            path=p.decode();entries.append((path,oid));oids.add(oid)
        trees[c]=entries
    proc=subprocess.Popen(['git','-C',str(ROOT),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    blobs={}
    for oid in sorted(oids):
        proc.stdin.write((oid+'\n').encode());proc.stdin.flush();h=proc.stdout.readline().split();data=proc.stdout.read(int(h[2]));assert proc.stdout.read(1)==b'\n';blobs[oid]=data
    proc.stdin.close();assert proc.wait()==0
    return commits,trees,blobs

def build_history():
    existing=(PRIVATE/'.git').exists()
    if existing:
        assert not run(['git','-C',str(PRIVATE),'status','--porcelain']).strip(),'Refuse to overwrite destination edits'
    PRIVATE.mkdir(exist_ok=True)
    if not existing:run(['git','init','--initial-branch=main',str(PRIVATE)])
    commits,trees,blobs=load_objects();source_head=git('rev-parse','HEAD').decode().strip()
    cache={};omitted=[];modified=[];marks={};nextmark=1
    stream=BASE/'screened-history.fast-import'
    with stream.open('wb') as f:
        for c in commits:
            for path,oid in trees[c]:
                key=(path,oid)
                if key in cache:continue
                out,reason=transform(path,blobs[oid])
                target=path
                if out is None:
                    omitted.append(dict(path=path,source_blob=oid,reason=reason));cache[key]=None;continue
                if reason=='reference-dependent non-Python source':target='redacted-sources/'+path+'.txt'
                mark=nextmark;nextmark+=1
                f.write(f'blob\nmark :{mark}\ndata {len(out)}\n'.encode());f.write(out);f.write(b'\n')
                cache[key]=(target,mark)
                if out!=blobs[oid]:modified.append(dict(path=path,source_blob=oid,source_sha256=sha(blobs[oid]),screened_sha256=sha(out),reason=reason or 'structured/privacy/reference sanitization'))
        for c in commits:
            obj=git('cat-file','-p',c);header,msg=obj.split(b'\n\n',1);parents=[];at=ct=None
            for line in header.decode().splitlines():
                if line.startswith('parent '):parents.append(line.split()[1])
                if line.startswith('author '):at=' '.join(line.rsplit(' ',2)[-2:])
                if line.startswith('committer '):ct=' '.join(line.rsplit(' ',2)[-2:])
            assert at and ct and len(parents)<=1
            mark=nextmark;nextmark+=1;marks[c]=mark;msg=safe_text(msg.decode()).encode()
            f.write(f'commit refs/heads/research-history\nmark :{mark}\nauthor {IDENT} {at}\ncommitter {IDENT} {ct}\ndata {len(msg)}\n'.encode());f.write(msg);f.write(b'\n')
            for p in parents:f.write(f'from :{marks[p]}\n'.encode())
            f.write(b'deleteall\n')
            for path,oid in trees[c]:
                item=cache[(path,oid)]
                if item is None:continue
                target,bm=item
                f.write(f'M 100644 :{bm} {json.dumps(target,ensure_ascii=False)}\n'.encode())
            f.write(b'\n')
        f.write(b'done\n')
    marksfile=BASE/'screened-marks.txt'
    with stream.open('rb') as inp:
        run(['git','-C',str(PRIVATE),'fast-import','--quiet','--done',f'--export-marks={marksfile}'],stdin=inp)
    imported={int(l.split()[0][1:]):l.split()[1] for l in marksfile.read_text().splitlines()}
    history_head=imported[marks[source_head]]
    if not existing:run(['git','-C',str(PRIVATE),'checkout','-b','main',history_head])
    else:
        run(['git','-C',str(PRIVATE),'checkout','main'])
        run(['git','-C',str(PRIVATE),'-c','user.name=Nikon Research Agent','-c','user.email=agent@localhost','merge','--no-ff','--no-commit','-X','theirs','research-history'])
    report=dict(policy=POLICY,source_head=source_head,source_commits=len(commits),screened_history_head=history_head,
        commit_mapping=[dict(source=c,screened=imported[marks[c]]) for c in commits],
        unique_path_blobs=len(cache),omitted=omitted,modified=modified,statistics=dict(stats),
        original_history_unchanged=True,qualification=f'{len(commits)} logical commits retained; contents/identities screened. This is not a byte-identical copy of original evidence. No original Git objects fetched.')
    (BASE/'private-history-export.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('commit_mapping','omitted','modified')},indent=2))

if __name__=='__main__':build_history()
