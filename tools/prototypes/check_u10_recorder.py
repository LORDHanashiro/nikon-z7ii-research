"""Independent HOST-only unpack/integrity/fault checks; no firmware or camera input."""
import argparse,binascii,json,pathlib,struct,subprocess,time
import numpy as np

def crc(b):return binascii.crc32(b)&0xffffffff
def read_exact(f,n):
    b=f.read(n)
    if len(b)!=n:raise ValueError('truncated record')
    return b
def validate(path,expected_pattern=True):
    hist=np.zeros(1024,dtype=np.uint64)
    with path.open('rb') as f:
        h=read_exact(f,64)
        if h[:8]!=b'N10PROT\0' or crc(h[:60])!=struct.unpack_from('<I',h,60)[0]:raise ValueError('header magic/CRC')
        version,w,height,stride,fn,fd,packing,source,fb,count,reserved,_=struct.unpack_from('<8I2Q2I',h,8)
        if version!=1 or packing!=1 or source!=1 or reserved or fn!=30000 or fd!=1001:raise ValueError('unsupported prototype contract')
        if not(0<w<=4096 and w%2==0 and 0<height<=2160 and 0<count<=256) or stride!=(w*5//2+63)//64*64 or fb!=stride*height:raise ValueError('invalid geometry')
        if 64+count*(fb+48)>512*1024*1024:raise ValueError('prototype size bound')
        for i in range(count):
            rh=read_exact(f,32);magic,seq,pts,n,pcrc,hcrc=struct.unpack('<4sIQQII',rh)
            if magic!=b'FRM1' or seq!=i or pts!=i*1000000000*fd//fn or n!=fb or crc(rh[:28])!=hcrc:raise ValueError('frame header')
            payload=read_exact(f,n)
            if crc(payload)!=pcrc:raise ValueError('payload CRC')
            foot=read_exact(f,16);magic2,seq2,pcrc2,fcrc=struct.unpack('<4sIII',foot)
            if magic2!=b'END1' or seq2!=i or pcrc2!=pcrc or crc(foot[:12])!=fcrc:raise ValueError('commit footer')
            rows=np.frombuffer(payload,dtype=np.uint8).reshape(height,stride)
            if np.any(rows[:,w*5//2:]):raise ValueError('nonzero row padding')
            groups=rows[:,:w*5//2].copy().reshape(height,w//2,5)
            word=np.zeros((height,w//2),dtype=np.uint64)
            for k in range(5):word|=groups[:,:,k].astype(np.uint64)<<(8*k)
            values=np.stack([(word>>(10*k))&1023 for k in range(4)],axis=2)
            hist+=np.bincount(values.ravel().astype(np.int64),minlength=1024).astype(np.uint64)
            if expected_pattern:
                pair=np.arange(w//2,dtype=np.uint64)[None,:];y=np.arange(height,dtype=np.uint64)[:,None]
                expected=[(17*i+3*pair+5*y+101)%1024,(19*i+2*pair+7*y)%1024,(23*i+11*pair+13*y+503)%1024,(19*i+2*pair+1+7*y)%1024]
                if any(not np.array_equal(values[:,:,k],x) for k,x in enumerate(expected)):raise ValueError('sample mismatch: low bits/order/frame reuse')
        if f.read(1):raise ValueError('trailing uncommitted data')
    return {'frames':count,'width':w,'height':height,'row_stride':stride,'samples':int(hist.sum()),'distinct_codes':int(np.count_nonzero(hist)),'low2_histogram':[int(hist[k::4].sum()) for k in range(4)],'sha_scope':'all samples checked against independent synthetic formula, not real precision measurement'}

def suite(binary,out):
    out.mkdir(parents=True,exist_ok=False);results=[]
    def run(name,w,h,frames,slots,*extra,should_fail=False):
        p=out/(name+'.n10proto');argv=[str(binary),'--output',str(p),'--width',str(w),'--height',str(h),'--frames',str(frames),'--slots',str(slots),*extra]
        cp=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100)
        if (cp.returncode!=0)!=should_fail:raise AssertionError((name,cp.returncode,cp.stdout,cp.stderr))
        row={'name':name,'argv':argv,'exit':cp.returncode,'writer':json.loads(cp.stdout),'stderr':cp.stderr,'file':p.name};results.append(row)
        return p,row
    p,row=run('padded-short-writes',130,37,9,2,'--short-write','257','--writer-delay-ms','3');row['reader']=validate(p)
    assert row['writer']['producer_waits']>0 and row['writer']['peak_slots_in_use']<=2
    for name,offset in [('bad-header',12),('bad-payload',64+32+7),('bad-footer',64+32+row['writer']['row_stride']*37+12)]:
        data=bytearray(p.read_bytes());data[offset]^=1;q=out/(name+'.n10proto');q.write_bytes(data)
        try:validate(q)
        except ValueError as e:results.append({'name':name,'rejected':True,'reason':str(e)})
        else:raise AssertionError(name+' silently accepted')
    q=out/'truncated.n10proto';q.write_bytes(p.read_bytes()[:-1])
    try:validate(q)
    except ValueError as e:results.append({'name':'truncated-footer','rejected':True,'reason':str(e)})
    else:raise AssertionError('truncation accepted')
    q,row=run('expanded-8bit-control',130,37,3,2,'--quantize-to-8');structural=validate(q,False)
    assert structural['low2_histogram'][1:]==[0,0,0]
    try:validate(q)
    except ValueError as e:row['independent_pattern_rejected']=str(e);row['structural_only']=structural
    else:raise AssertionError('expanded 8-bit negative control accepted as original codes')
    q,row=run('injected-host-write-error',130,37,15,2,'--fail-after','18000',should_fail=True)
    assert not row['writer']['complete'] and not row['writer']['host_fsync_completed']
    try:validate(q)
    except ValueError as e:row['reader_rejected']=str(e)
    else:raise AssertionError('failed run accepted as complete')
    for name,w,h,frames in [('hd',1920,1080,12),('uhd',3840,2160,8)]:
        p,row=run(name,w,h,frames,3);before=time.monotonic();row['reader']=validate(p);row['reader_seconds']=time.monotonic()-before
        assert row['reader']['distinct_codes']==1024 and all(row['reader']['low2_histogram'])
        row['host_end_to_end_MBps']=row['writer']['bytes']/row['writer']['elapsed_ns']*1000
    summary={'scope':'HOST-ONLY; arbitrary synthetic code values, NOT N-Log or Nikon data','passed':True,'runs':results,'limitations':['No camera ISP/DMA/encoder/card behavior proved.','CRC and footer detect tested faults; not a general power-loss or bit-error proof.','fsync and throughput refer to this host filesystem; no camera performance extrapolation.','Sequential validation proves no corruption in these runs, not a general concurrent algorithm proof.']}
    (out/'result.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args();suite(a.binary.resolve(),a.output.resolve())
