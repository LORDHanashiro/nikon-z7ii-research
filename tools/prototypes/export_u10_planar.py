"""HOST synthetic record adapter. No Nikon packing or camera source assumptions."""
from pathlib import Path
import binascii,struct,hashlib
import numpy as np

def crc(b):return binascii.crc32(b)&0xffffffff
def exact(f,n):
 b=f.read(n)
 if len(b)!=n:raise ValueError('truncated synthetic record')
 return b

def export(source:Path,output:Path,limit:int):
 with source.open('rb') as f:
  h=exact(f,64)
  if h[:8]!=b'N10PROT\0' or crc(h[:60])!=struct.unpack_from('<I',h,60)[0]:raise ValueError('header magic/CRC')
  version,w,height,stride,fn,fd,packing,kind,fb,count,reserved,_=struct.unpack_from('<8I2Q2I',h,8)
  if (version,packing,kind,fn,fd,reserved)!=(1,1,1,30000,1001,0):raise ValueError('unsupported SYNTHETIC contract')
  if not(0<w<=4096 and w%2==0 and 0<height<=2160 and 0<count<=256):raise ValueError('geometry/count')
  if stride!=(w*5//2+63)//64*64 or fb!=stride*height or 64+count*(48+fb)>512*1024**2:raise ValueError('span/size')
  n=min(limit,count)
  if n<=0 or w*height*4*n>512*1024**2:raise ValueError('output bound')
  with output.open('xb') as out:
   for seq in range(n):
    rh=exact(f,32);magic,i,pts,length,pcrc,hcrc=struct.unpack('<4sIQQII',rh)
    if magic!=b'FRM1' or i!=seq or pts!=seq*10**9*fd//fn or length!=fb or crc(rh[:28])!=hcrc:raise ValueError('frame header/PTS')
    payload=exact(f,fb)
    if crc(payload)!=pcrc:raise ValueError('payload CRC')
    foot=exact(f,16);m,j,pc,fc=struct.unpack('<4sIII',foot)
    if m!=b'END1' or j!=seq or pc!=pcrc or crc(foot[:12])!=fc:raise ValueError('commit footer')
    rows=np.frombuffer(payload,np.uint8).reshape(height,stride)
    if np.any(rows[:,w*5//2:]):raise ValueError('row padding')
    groups=rows[:,:w*5//2].reshape(height,w//2,5);word=np.zeros((height,w//2),np.uint64)
    for k in range(5):word|=groups[:,:,k].astype(np.uint64)<<(8*k)
    y=np.empty((height,w),dtype='<u2');y[:,::2]=(word>>10)&1023;y[:,1::2]=(word>>30)&1023
    u=(word&1023).astype('<u2');v=((word>>20)&1023).astype('<u2')
    for plane in [y,u,v]:out.write(plane.tobytes())
   if n==count and f.read(1):raise ValueError('trailing record bytes')
 return {'width':w,'height':height,'frames':n,'source_frames':count,'selected_prefix_only':n<count,'fps_num':fn,'fps_den':fd,'source_row_stride':stride,'source_contract':'SYNTHETIC_NOT_NLOG_U_Y0_V_Y1_10BIT_TIGHT40','output_format':'yuv422p10le','output_bytes':output.stat().st_size,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
