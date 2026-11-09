"""Recover only validated prefix of HOST synthetic prototype. Never changes input."""
import argparse,binascii,hashlib,json,os,pathlib,struct
from check_u10_recorder import validate

def crc(b):return binascii.crc32(b)&0xffffffff
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()
def scan(source):
    if source.stat().st_size>512<<20:raise ValueError('input cap')
    original_sha=sha(source);records=[];last_good=64;reason=None
    with source.open('rb') as f:
        h=f.read(64)
        if len(h)!=64 or h[:8]!=b'N10PROT\0' or crc(h[:60])!=struct.unpack_from('<I',h,60)[0]:raise ValueError('untrusted overall header; no geometry guessing')
        version,w,height,stride,fn,fd,packing,origin,fb,count,reserved,_=struct.unpack_from('<8I2Q2I',h,8)
        if version!=1 or packing!=1 or origin!=1 or reserved or fn!=30000 or fd!=1001:raise ValueError('unsupported prototype header')
        if not(0<w<=4096 and w%2==0 and 0<height<=2160 and 0<count<=256) or stride!=(w*5//2+63)//64*64 or fb!=stride*height or 64+count*(fb+48)>512<<20:raise ValueError('bounded geometry/count')
        for i in range(count):
            rh=f.read(32)
            if len(rh)!=32:reason='partial frame header';break
            magic,seq,pts,n,pcrc,hcrc=struct.unpack('<4sIQQII',rh)
            if magic!=b'FRM1' or seq!=i or pts!=i*1000000000*fd//fn or n!=fb or crc(rh[:28])!=hcrc:reason='invalid frame header';break
            payload=f.read(n)
            if len(payload)!=n:reason='partial payload';break
            if crc(payload)!=pcrc:reason='invalid payload CRC';break
            foot=f.read(16)
            if len(foot)!=16:reason='partial footer';break
            magic2,seq2,check,fc=struct.unpack('<4sIII',foot)
            if magic2!=b'END1' or seq2!=i or check!=pcrc or crc(foot[:12])!=fc:reason='invalid footer';break
            last_good=f.tell();records.append({'seq':i,'payload_crc':pcrc,'end_offset':last_good})
        if reason is None and f.read(1):reason='extra trailing data'
    return {'source_sha256':original_sha,'source_complete':reason is None and len(records)==count,'source_declared_frames':count,'validated_prefix_frames':len(records),'prefix_end':last_good,'stop_reason':reason,'records':records,'scope':'HOST synthetic file integrity only, not original recording success/powerloss/camera'},h

def recover(source,target,receipt):
    r,h=scan(source);before=r['source_sha256']
    if r['validated_prefix_frames']:
        revised=bytearray(h);struct.pack_into('<Q',revised,48,r['validated_prefix_frames']);struct.pack_into('<I',revised,60,crc(revised[:60]))
        with source.open('rb') as inp,target.open('xb') as out:
            inp.seek(64);out.write(revised);remaining=r['prefix_end']-64
            while remaining:
                block=inp.read(min(remaining,1<<20))
                if not block:raise ValueError('source changed during recovery')
                out.write(block);remaining-=len(block)
            out.flush();os.fsync(out.fileno())
        r['recovered_copy_sha256']=sha(target);r['independent_samples']=validate(target)
    else:r['recovered_copy_created']=False
    assert sha(source)==before==r['source_sha256'];r['original_unchanged']=True
    r['qualification']='New synthetic-format copy count/CRC reflects validated prefix only. Incomplete/corrupt original is never relabeled success.'
    with receipt.open('x') as out:json.dump(r,out,indent=2);out.write('\n')
    return r

def suite(out):
    out.mkdir(parents=True,exist_ok=False);root=pathlib.Path.cwd();base=root/'logs/research/EXP-0102/suite-01/padded-short-writes.n10proto';data=base.read_bytes();fb=struct.unpack_from('<Q',data,40)[0];rs=fb+48;results=[]
    cuts=[0,63,64,65,95,96,64+32+fb-1,64+32+fb,64+rs-1,64+rs,64+rs+1,64+2*rs-1,len(data)-1,len(data)]
    for i,cut in enumerate(cuts):
        p=out/f'cut-{i:02}.n10proto';p.write_bytes(data[:cut]);expected=0 if cut<64 else min(9,(cut-64)//rs)
        try:r=recover(p,out/f'prefix-{i:02}.n10proto',out/f'receipt-{i:02}.json')
        except ValueError as e:
            assert cut<64;results.append({'cut':cut,'rejected_header':str(e)});continue
        assert r['validated_prefix_frames']==expected and r['source_complete']==(cut==len(data));results.append({'cut':cut,'prefix_frames':expected,'source_complete':r['source_complete'],'stop_reason':r['stop_reason']})
    p=out/'corrupt-second-payload.n10proto';bad=bytearray(data);bad[64+rs+32+7]^=1;p.write_bytes(bad);r=recover(p,out/'corrupt-recovered.n10proto',out/'corrupt-receipt.json');assert r['validated_prefix_frames']==1 and not r['source_complete'];results.append({'case':'corrupt-second-frame','prefix_frames':1,'stop_reason':r['stop_reason']})
    p=root/'logs/research/EXP-0102/suite-01/injected-host-write-error.n10proto';r=recover(p,out/'injected-error-recovered.n10proto',out/'injected-error-receipt.json');assert r['validated_prefix_frames']==1 and not r['source_complete'];results.append({'case':'actual injected HOST write failure output','prefix_frames':1,'source_complete':False,'samples':r['independent_samples']})
    sparse=out/'oversize-sparse.invalid'
    with sparse.open('xb') as f:f.truncate((512<<20)+1)
    try:recover(sparse,out/'oversize-not-created.n10proto',out/'oversize-not-created.json')
    except ValueError as e:
        assert str(e)=='input cap';results.append({'case':'sparse input above512MiB rejected before hashing','rejected':True,'reason':str(e),'logical_bytes':sparse.stat().st_size,'allocated_bytes':sparse.stat().st_blocks*512})
    else:raise AssertionError('oversize input admitted')
    result={'passed':True,'scope':'Finite HOST synthetic prefix recovery; no device/powerloss/recording-success proof','cases':results,'limitations':['No scanpastfirstbadframe/no guessed bytes or CRCrepair','Copy headercountchangesonlyreflectvalidprefix; sourceSHAretained','Durability on actualcamera/card, liveframe lifetime and10bitNLogsourceUNKNOWN']}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=pathlib.Path);suite(p.parse_args().output)
