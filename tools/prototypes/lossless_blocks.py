"""HOST-only bounded block transport with raw fallback; not a Nikon/video codec."""
import argparse,binascii,hashlib,json,os,pathlib,random,struct,time,zlib
from check_u10_recorder import validate

def crc(b):return binascii.crc32(b)&0xffffffff
def read_exact(f,n):
    b=f.read(n)
    if len(b)!=n:raise ValueError('truncated stream')
    return b
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def encode(source,target,blocksize=1<<20):
    total=source.stat().st_size
    if not 0<blocksize<=1<<20 or total>512<<20:raise ValueError('prototype size cap')
    count=(total+blocksize-1)//blocksize;head=struct.pack('<8sIIQI',b'N10BLK1\0',1,blocksize,total,count);head+=struct.pack('<I',crc(head))
    before=time.perf_counter();raw_blocks=compressed_blocks=0
    with source.open('rb') as f,target.open('xb') as out:
        out.write(head)
        for seq in range(count):
            raw=read_exact(f,min(blocksize,total-seq*blocksize));encoded=zlib.compress(raw,level=1)
            method=1 if len(encoded)<len(raw) else 0;stored=encoded if method else raw
            raw_blocks+=method==0;compressed_blocks+=method==1
            h=struct.pack('<5I',method,seq,len(raw),len(stored),crc(raw));h+=struct.pack('<I',crc(h))
            out.write(h);out.write(stored)
        if f.read(1):raise ValueError('source changed size')
        out.flush();os.fsync(out.fileno())
    size=target.stat().st_size;bound=total+32+24*count;assert size<=bound
    return {'source_bytes':total,'encoded_bytes':size,'bound_bytes':bound,'raw_blocks':raw_blocks,'compressed_blocks':compressed_blocks,'seconds_with_host_fsync':time.perf_counter()-before,'source_sha256':digest(source),'encoded_sha256':digest(target)}

def decode(source,target):
    before=time.perf_counter()
    with source.open('rb') as f,target.open('xb') as out:
        h=read_exact(f,32);magic,version,blocksize,total,count,headercrc=struct.unpack('<8sIIQII',h)
        if magic!=b'N10BLK1\0' or version!=1 or crc(h[:28])!=headercrc:raise ValueError('header')
        if not 0<blocksize<=1<<20 or total>512<<20 or count!=(total+blocksize-1)//blocksize:raise ValueError('size cap/count')
        for seq in range(count):
            h=read_exact(f,24);method,index,n,storedsize,pcrc,hcrc=struct.unpack('<6I',h)
            if crc(h[:20])!=hcrc or index!=seq or n!=min(blocksize,total-seq*blocksize):raise ValueError('chunk header/shape')
            if method not in (0,1) or not 0<storedsize<=n or (method==0 and storedsize!=n) or (method==1 and storedsize>=n):raise ValueError('chunk method/size')
            stored=read_exact(f,storedsize)
            if method:
                d=zlib.decompressobj();raw=d.decompress(stored,n+1)
                if len(raw)!=n or not d.eof or d.unused_data or d.unconsumed_tail:raise ValueError('bounded decompression/EOF')
            else:raw=stored
            if crc(raw)!=pcrc:raise ValueError('payload CRC')
            out.write(raw)
        if f.read(1):raise ValueError('trailing data')
        out.flush();os.fsync(out.fileno())
    return {'decoded_bytes':target.stat().st_size,'sha256':digest(target),'seconds_with_host_fsync':time.perf_counter()-before}

def suite(out):
    out.mkdir(parents=True,exist_ok=False);r=pathlib.Path.cwd();results=[]
    uniform=out/'uniform-bytes.dat';uniform.write_bytes(random.Random(0x107).randbytes(8<<20))
    small=out/'small-fixture.dat';small.write_bytes(bytes(range(256))*31+b'partial-block')
    sources=[('synthetic_u10',r/'logs/research/EXP-0102/suite-01/hd.n10proto'),('uniform_bytes',uniform),('small',small),('expanded8bit_control',r/'logs/research/EXP-0102/suite-01/expanded-8bit-control.n10proto')]
    for name,p in sources:
        encoded=out/(name+'.blocks');decoded=out/(name+'.restored');enc=encode(p,encoded);dec=decode(encoded,decoded);assert dec['sha256']==enc['source_sha256']
        row={'name':name,'encode':enc,'decode':dec}
        if name=='synthetic_u10':row['independent_samples']=validate(decoded)
        if name=='uniform_bytes':assert enc['raw_blocks']==8 and enc['compressed_blocks']==0
        if name=='expanded8bit_control':
            structural=validate(decoded,False);assert structural['low2_histogram'][1:]==[0,0,0]
            try:validate(decoded)
            except ValueError as e:row['low_bit_loss_still_rejected']=str(e)
            else:raise AssertionError('compression appeared to restore lost bits')
        results.append(row)
    base=(out/'small.blocks').read_bytes()
    for name in ['bad_header','bad_chunk_header','bad_payload','truncated','oversize_chunk','trailing']:
        data=bytearray(base)
        if name=='bad_header':data[12]^=1
        elif name=='bad_chunk_header':data[40]^=1
        elif name=='bad_payload':data[56+7]^=1
        elif name=='truncated':data=data[:-1]
        elif name=='trailing':data+=b'X'
        elif name=='oversize_chunk':
            struct.pack_into('<I',data,40,(1<<20)+1);struct.pack_into('<I',data,52,crc(data[32:52]))
        p=out/(name+'.blocks');p.write_bytes(data)
        try:decode(p,out/(name+'.rejected-output'))
        except (ValueError,zlib.error) as e:results.append({'name':name,'rejected':True,'reason':str(e)})
        else:raise AssertionError(name+' accepted')
    result={'scope':'HOST-only synthetic lossless component; no source/NLog/camera codec/performance evidence','passed':True,'zlib_runtime':zlib.ZLIB_RUNTIME_VERSION,'runs':results,'limitations':['Structured fixtures are not representative NLog scenes; compression ratio not predicted.','Raw fallback bounds wrapper expansion, not worst-case storage rate reduction.','No live-source ownership, camera cache/CPU/API/card integration or playback container proved.','Roundtrip/tests prove tested properties; not all possible corruptions or power loss.']}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=pathlib.Path);suite(p.parse_args().output)
