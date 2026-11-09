"""Finite HOST-only hypothetical sink plan, never issues device/file writes.

Matches selected arithmetic from EXP0117, with explicit additional host guards.
Does not emulate NVMe, prove copy-helper behavior or recover actual image format.
"""
import argparse, hashlib, json, pathlib
from fractions import Fraction

def ceil_div(a,b): return (a+b-1)//b

def plan(payload, block=512, ioalign=64, pointer=0x20000000, mdts=0,
         mpsmin=0, lba=0xfffffff0):
    if not 0<payload<=512<<20: raise ValueError('payload bound')
    if block not in (512,4096): raise ValueError('unsupported block hypothesis')
    if ioalign not in (0,1) and not(1<ioalign<=4096 and ioalign&(ioalign-1)==0):
        raise ValueError('ioalign hypothesis')
    if not (0<=mdts<=8 and 0<=mpsmin<=15): raise ValueError('shift hypothesis')
    bounce=ioalign!=0 and pointer&(ioalign-1)!=0
    if bounce: k=4096//block
    elif mdts:
        k=(((1<<(12+mpsmin))<<mdts)&0xffffffff)//block
    else:k=1024
    if not 1<=k<=65536:raise ValueError('zero or unrepresentable NLB chunk')
    blocks=ceil_div(payload,block);span=blocks*block
    if not 0<=lba<=2**64-blocks:raise ValueError('LBA64 wrap')
    if not 0<=pointer<2**32 or pointer+span>2**32:raise ValueError('pointer32 wrap')
    if ceil_div(blocks,k)>20000:raise ValueError('finite command bound')
    remaining=blocks;p=pointer;pos=lba;commands=[];request_end=pointer
    while remaining:
        n=min(k,remaining);bytecount=n*block
        request_bytes=4096 if bounce else bytecount
        request_end=max(request_end,p+request_bytes)
        if request_end>2**32:raise ValueError('helper request pointer32 wrap')
        commands.append({'lba':pos,'blocks':n,'nlb16':n-1,'source':p,
                         'transfer_bytes':bytecount,'source_request_bytes':request_bytes})
        remaining-=n;p+=bytecount;pos+=n
    return {'payload':payload,'block_bytes':block,'ioalign':ioalign,'pointer':pointer,
            'MDTS_hypothesis':mdts,'MPSMIN_hypothesis':mpsmin,
            'bounce_request_path':bool(bounce),'chunk_limit_blocks':k,
            'blocks':blocks,'transfer_span':span,'block_padding':span-payload,
            'commands':commands,'source_request_extent':request_end-pointer,
            'potential_request_tail_past_transfer':max(0,request_end-pointer-span),
            'qualification':'Arithmetic-only; request-length does not prove actual helper read or DMA visibility.'}

def audit(x):
    # Independent closed forms and interval accounting, no plan() call.
    ns=(x['payload']+x['block_bytes']-1)//x['block_bytes']
    q,r=divmod(ns,x['chunk_limit_blocks']);num=q+(r!=0)
    assert num==len(x['commands']) and ns==sum(c['blocks'] for c in x['commands'])
    first=x['commands'][0];p=first['source'];lba=first['lba'];nbytes=0
    for c in x['commands']:
        assert c['source']==p and c['lba']==lba
        assert 0<=c['nlb16']<=65535 and c['blocks']==c['nlb16']+1
        assert c['transfer_bytes']==c['blocks']*x['block_bytes']
        p+=c['transfer_bytes'];lba+=c['blocks'];nbytes+=c['transfer_bytes']
    expected_extent=num*4096 if x['bounce_request_path'] else nbytes
    assert x['source_request_extent']==expected_extent
    assert nbytes==ns*x['block_bytes']==x['transfer_span']
    assert 0<=x['block_padding']<x['block_bytes']
    return {'commands':num,'closed_form_extent':expected_extent,'passed':True}

def suite(out):
    out.mkdir(parents=True,exist_ok=False);cases=[]
    for w,h in [(130,37),(1920,1080),(3840,2160)]:
        stride=ceil_div(w*5//2,64)*64
        for b in (512,4096):
            for mdts in (0,8):
                for misalign in (False,True):
                    x=plan(stride*h,b,pointer=0x20000000+int(misalign),mdts=mdts)
                    x.update(width=w,height=h,row_stride=stride)
                    x['independent_audit']=audit(x)
                    file=out/f'{w}x{h}-b{b}-d{mdts}-unaligned{int(misalign)}.json'
                    file.write_text(json.dumps(x,indent=2)+'\n')
                    summary={k:v for k,v in x.items() if k not in ('commands','qualification')}
                    summary['command_count']=len(x['commands']);summary['raw_file']=str(file)
                    summary['raw_sha256']=hashlib.sha256(file.read_bytes()).hexdigest()
                    summary['payload_MBps_at_assumed_30000_1001']=float(Fraction(stride*h*30000,1001*10**6))
                    cases.append(summary)
    negative=[]
    for label,kwargs in [('zero-payload',{'payload':0}),('not-supported-block',{'payload':512,'block':8192}),
                         ('not-power2-align',{'payload':512,'ioalign':3}),
                         ('capacity-shift-wrap',{'payload':512,'mdts':8,'mpsmin':15}),
                         ('NLB-over16',{'payload':512,'mdts':8,'mpsmin':6}),
                         ('source32-wrap',{'payload':4096,'pointer':0xfffffe00,'ioalign':0}),
                         ('LBA64-wrap',{'payload':4096,'lba':2**64-1})]:
        try:plan(**kwargs)
        except ValueError as e:negative.append({'case':label,'rejected':True,'reason':str(e)})
        else:raise AssertionError(label+' accepted')
    # Boundary cases confirm zero/one IoAlign and exact16bit NLB are representable.
    boundaries=[]
    for alignment in (0,1):
        p=plan(512,ioalign=alignment,pointer=0x20000001);audit(p)
        assert not p['bounce_request_path'];boundaries.append({'ioalign':alignment,'no_bounce':True})
    p=plan(65536*512,mdts=8,mpsmin=5);audit(p)
    assert len(p['commands'])==1 and p['commands'][0]['nlb16']==65535
    boundaries.append({'exact65536blocks':True,'nlb16':65535})
    result={'experiment':'EXP-0118','scope':'Conditional HOST-only span/chunk/request planner, no media I/O',
            'passed':True,'cases':cases,'negative_controls':negative,'boundaries':boundaries,
            'limits':['Pixelpacking/tight10bit422/rowstride/blocksize/IoAlign/MDTS/MPSMIN/sourcepointer are hypothetical.',
                      'No camera timing/codec/card/FS/cache/physicaladdress or NLog precision proved.',
                      'Fixed4KiB source request is conditional on unexpanded helper copying requested length; no real overread claim.',
                      'Additional guards are proposed host design; not recovered camera error handling.',
                      'Payload only, does not implement record headers/file allocation/close/Flush or bufferownership.']}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'cases':len(cases),'negative':len(negative),'boundaries':len(boundaries),
                      'scope':result['scope'],'uhd_b512_default':[{k:c[k] for k in ('width','block_bytes','MDTS_hypothesis','bounce_request_path','command_count','potential_request_tail_past_transfer')} for c in cases if c['width']==3840 and c['block_bytes']==512 and c['MDTS_hypothesis']==0]},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=pathlib.Path);suite(p.parse_args().output)
