"""Finite HOST-only recording design model. No firmware/hardware events are executed."""
import argparse,bisect,json,pathlib
from fractions import Fraction as F

def finish(start,work,rate,outages):
    t=start;remaining=F(work,rate)
    for a,b in outages:
        if t>=b:continue
        if t<a:
            take=min(remaining,a-t);remaining-=take;t+=take
            if remaining==0:return t
        if a<=t<b:t=b
    return t+remaining

def capacity(start,end,rate,outages):
    # Independent integral check, rather than calling the service scheduler.
    blocked=sum((max(F(0),min(end,b)-max(start,a)) for a,b in outages),F(0))
    return (end-start-blocked)*rate

def trace(arrivals,work,rate,outages):
    completions=[];last=F(0)
    for a in arrivals:
        start=max(a,last);d=finish(start,work,rate,outages)
        assert capacity(start,d,rate,outages)==work
        assert d>start and not any(a<d<b for a,b in outages)
        completions.append(d);last=d
    return completions

def peak_by_events(arrivals,completions):
    events=sorted([(t,1) for t in arrivals]+[(t,-1) for t in completions]) # Free at exact tie first.
    used=peak=0
    for _,delta in events:
        used+=delta;assert used>=0;peak=max(peak,used)
    assert used==0
    return peak

def admitted_prefix(arrivals,work,rate,outages,slots):
    pending=[];done=0;accepted=0;last=F(0)
    for i,a in enumerate(arrivals):
        while pending and pending[0]<=a:pending.pop(0);done+=1
        assert done+len(pending)==accepted
        if len(pending)==slots:return {'stopped_before_frame':i,'accepted':accepted,'completed_at_stop':done,'inflight_at_stop':len(pending),'policy':'stop; never overwrite or pretend lossless continuation'}
        last=finish(max(a,last),work,rate,outages);pending.append(last);accepted+=1
        assert len(pending)<=slots
    return {'stopped_before_frame':None,'accepted':accepted,'completed_at_last_arrival':done,'inflight_at_last_arrival':len(pending),'policy':'finite trace admitted; not unlimited guarantee'}

def check_case(work,rate,period,n,blackout):
    arrivals=[i*period for i in range(n)];outages=[] if not blackout else [tuple(blackout)]
    completions=trace(arrivals,work,rate,outages)
    depths=[i+1-bisect.bisect_right(completions,a) for i,a in enumerate(arrivals)]
    peak=max(depths);assert peak==peak_by_events(arrivals,completions)
    r=admitted_prefix(arrivals,work,rate,outages,3)
    first=next((i for i,x in enumerate(depths) if x>3),None);assert r['stopped_before_frame']==first
    return {'min_slots_for_declared_trace':peak,'record_slot_bytes_only':peak*work,'three_slot_policy':r,'last_completion_s':{'n':completions[-1].numerator,'d':completions[-1].denominator},'max_completion_lag_ms':float(max(d-a for a,d in zip(arrivals,completions))*1000)}

def main(out):
    out.mkdir(parents=True,exist_ok=False)
    # Analytic edge cases independent of the image scenarios.
    assert check_case(1,1,F(1),6,None)['min_slots_for_declared_trace']==1
    assert check_case(1,1,F(1),6,[F(0),F(3)])['min_slots_for_declared_trace']==4
    assert check_case(1,F(1,2),F(1),6,None)['min_slots_for_declared_trace']==4
    w,h=3840,2160;layouts={'tight10_422':w*h*5//2,'u16_422':w*h*4,'tight10_420':w*h*15//8};cases=[]
    specs=[('tight10_422',650_000_000,x) for x in [0,50,120,250]]+[
        ('tight10_422',500_000_000,0),('tight10_422',1_000_000_000,120),
        ('u16_422',1_000_000_000,120),('u16_422',900_000_000,0),('tight10_420',500_000_000,120)]
    for layout,rate,ms in specs:
        outage=None if not ms else [F(1,4),F(1,4)+F(ms,1000)]
        row={'layout_hypothesis':layout,'frame_bytes':layouts[layout],'width':w,'height':h,'frames':90,'fps':{'n':30000,'d':1001},'assumed_effective_service_bytes_s':rate,'blackout_ms':ms,'blackout_start_ms':250 if ms else None}
        row.update(check_case(layouts[layout],rate,F(1001,30000),90,outage));cases.append(row)
    result={'experiment':'EXP-0106','scope':'EXACT CONDITIONAL HOST DESIGN MODEL; not a camera timing/performance observation','passed':True,'analytic_cases_checked':3,'scenarios':cases,'qualification':['All rates/layouts/outages are explicit hypotheses; source/SPS/NLog/packing not recovered.','Frame arrival instantaneous, one FIFO writer; service rate is an assumed effective whole-stage rate.','Min slots only for these finite traces; arbitrarily long outage cannot be tolerated by finite lossless buffers.','No reserved camera memory, processor/cache traffic, thermal or card latency measurements.','Synthetic completion timestamps are internal arithmetic only; no firmware/QEMU/device state is driven.']}
    (out/'envelope.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('output',type=pathlib.Path);main(a.parse_args().output)
