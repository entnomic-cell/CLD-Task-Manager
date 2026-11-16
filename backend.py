# Forensic backend (Windows, run as Administrator). pip install psutil
import ctypes,hashlib,json,os,platform,queue,re,subprocess,sys,threading,time
from ctypes import wintypes as W
from urllib.parse import unquote
import psutil
from concurrent.futures import ThreadPoolExecutor,as_completed

try:
    import yara
except ImportError as e:
    yara=None
    YARA_ERROR=f"YARA is unavailable: {e}"

LK=threading.Lock()
def emit(o):
    with LK: print(json.dumps(o),flush=True)

HERE=os.path.dirname(os.path.abspath(__file__))
try: GEN=[x.strip().lower() for x in open(os.path.join(HERE,'generics.txt'),encoding='utf8') if x.strip() and not x.startswith('#')]
except OSError: GEN=[]

YARA_RULES=None;YARA_COUNT=5089;YARA_RELEASE='20261115'
YARA_PATH=os.path.join(HERE,'rules','yara-rules-core.yar')
if yara is not None:
    try:
        YARA_RULES=yara.compile(filepath=YARA_PATH)
        YARA_ERROR=''
    except Exception as e:
        YARA_ERROR=f"Could not compile YARA database: {e}"

# ---- process memory reader ----
K=ctypes.WinDLL('kernel32',use_last_error=True)
class MBI(ctypes.Structure):
    _fields_=[('b',ctypes.c_void_p),('ab',ctypes.c_void_p),('ap',W.DWORD),('sz',ctypes.c_size_t),('st',W.DWORD),('pr',W.DWORD),('ty',W.DWORD)]
K.OpenProcess.restype=ctypes.c_void_p
K.VirtualQueryEx.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(MBI),ctypes.c_size_t]
K.ReadProcessMemory.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
K.CloseHandle.argtypes=[ctypes.c_void_p]
PA=re.compile(rb'[A-Za-z]:\\[\x20-\x7e]{3,240}?\.(?:exe|dll|jar|ico|sys)',re.I)
PW=re.compile(rb'[A-Za-z]\x00:\x00\\\x00(?:[\x20-\x7e]\x00){3,240}?\.\x00(?:e\x00x\x00e\x00|d\x00l\x00l\x00|j\x00a\x00r\x00)',re.I)
PF=re.compile(rb'file:///[\x20-\x7e]{4,260}')
def grab(d,found):  # fast: find() literal anchors (C speed), regex only at hits
    for nd,back,rx in ((b':\\',1,PA),(b':\x00\\\x00',2,PW),(b'file:///',0,PF)):
        i=d.find(nd)
        while i>=0:
            if i>=back:
                m=rx.match(d,i-back)
                if m: found.add(m.group())
            i=d.find(nd,i+1)

def read_mem(pid):
    h=K.OpenProcess(0x410,False,pid)
    if not h: return None
    buf=ctypes.create_string_buffer(1<<22);found=set();ok=True;m=MBI();a=0
    while K.VirtualQueryEx(h,a,ctypes.byref(m),ctypes.sizeof(m)):
        base=m.b or 0
        if m.st==0x1000 and m.pr and not m.pr&0x101 and m.ty!=0x1000000:
            off=0
            while off<m.sz:
                r=ctypes.c_size_t()
                if not K.ReadProcessMemory(h,base+off,buf,min(len(buf),m.sz-off),ctypes.byref(r)): ok=False
                if r.value: grab(ctypes.string_at(buf,r.value),found)
                off+=len(buf)-256
        a=base+m.sz
    K.CloseHandle(h)
    yara_result={'status':'unavailable' if YARA_RULES is None else 'clear','matches':[]}
    if YARA_RULES is None:
        yara_result['error']=YARA_ERROR or 'YARA database is unavailable'
    else:
        try:
            for match in YARA_RULES.match(pid=pid,timeout=15):
                yara_result['matches'].append({
                    'name':match.rule,
                    'description':str(match.meta.get('description','')),
                    'author':str(match.meta.get('author','')),
                })
            yara_result['status']='matches' if yara_result['matches'] else 'clear'
        except Exception as e:
            yara_result={'status':'error','matches':[],'error':str(e)}
    return found,ok,yara_result

# key: (kind, name, "Seen in" label, "Ran" label)
SRC={'DiagTrack':('svc','DiagTrack','DiagTrack memory','Since service start'),
     'AppInfo':('svc','Appinfo','AppInfo memory','Since service start'),
     'DPS':('svc','DPS','DPS memory','This or an earlier boot'),
     'PcaSvc':('svc','PcaSvc','PcaSvc memory','This or an earlier boot'),
     'DcomLaunch':('svc','DcomLaunch','DcomLaunch memory','Since service start'),
     'file:///':('proc','explorer.exe','Explorer · file:///','—'),
     'Explorer JARs':('proc','explorer.exe','Explorer · JARs','—'),
     'TextInputHost':('proc','TextInputHost.exe','TextInputHost memory','—')}

def pid_of(kind,name):
    if kind=='svc':
        try: return psutil.win_service_get(name).pid()
        except Exception: return None
    for p in psutil.process_iter(['name']):
        if (p.info['name'] or '').lower()==name.lower(): return p.pid

PROG={'d':0,'t':0,'on':True}
def rows_for(key,found,seen):
    kind,name,label,ran=SRC[key];out=[]
    for s in found:
        isf=s.startswith(b'file:///')
        if isf!=(key=='file:///'): continue
        p=unquote(s[8:].decode('latin1')).replace('/','\\') if isf else (s.decode('utf-16le') if s[1:2]==b'\x00' else s.decode('latin1'))
        if key=='Explorer JARs' and not p.lower().endswith('.jar'): continue
        if (key,p.lower()) in seen: continue
        seen.add((key,p.lower()))
        out.append({'n':os.path.basename(p),'k':key,'src':label,'ran':ran,'p':p,'gen':next((g for g in GEN if g in p.lower()),'')})
    return out

def scan(cur):  # one thread per target process; rows stream into `cur` as each finishes
    pids={k:pid_of(v[0],v[1]) for k,v in SRC.items()};uniq=sorted({p for p in pids.values() if p})
    part=any(p is None for p in pids.values());seen=set();yara_by_pid={}
    PROG.update(d=0,t=len(uniq),on=True)
    with ThreadPoolExecutor(max(1,len(uniq))) as ex:
        futs={ex.submit(read_mem,p):p for p in uniq}
        for f in as_completed(futs):
            r=f.result()
            if r is None:
                part=True
                yara_by_pid[str(futs[f])]={'status':'unavailable','matches':[]}
            else:
                part|=not r[1];yara_by_pid[str(futs[f])]=r[2]
                for k in SRC:
                    if pids[k]==futs[f]:
                        new=rows_for(k,r[0],seen);cur.extend(new)
                        for x in new: want(x['p'])
            PROG['d']+=1
    return part,yara_by_pid

# ---- signature / description / icon cache (parallel PowerShell workers) ----
META={};SEEN=set();MQ=queue.Queue();ICONS={}
def want(p):
    k=p.lower()
    if k in SEEN: return
    SEEN.add(k)
    if not os.path.exists(p): META[k]=('Missing','','','','')
    else: MQ.put(p)

PS=("Add-Type -AssemblyName System.Drawing;$ErrorActionPreference='SilentlyContinue';$l=ConvertFrom-Json([Console]::In.ReadToEnd());"
    "ConvertTo-Json -Compress -InputObject @($l|%{$p=$_;$pe=[IO.Path]::GetExtension($p).ToLower() -in '.exe','.dll','.sys';$ic='';"
    "try{$icon=[Drawing.Icon]::ExtractAssociatedIcon($p);if($icon){$bitmap=$icon.ToBitmap();$m=New-Object IO.MemoryStream;"
    "$bitmap.Save($m,[Drawing.Imaging.ImageFormat]::Png);$ic=[Convert]::ToBase64String($m.ToArray());$m.Dispose();$bitmap.Dispose();$icon.Dispose()}}catch{};"
    "$s='';$d='';$pub='';$signer='';if($pe){$a=Get-AuthenticodeSignature -LiteralPath $p;$s=[string]$a.Status;"
    "$signer=[string]$a.SignerCertificate.Subject;$v=(Get-Item -LiteralPath $p).VersionInfo;$d=$v.FileDescription;$pub=$v.CompanyName};"
    "[pscustomobject]@{p=$p;s=$s;d=$d;i=$ic;pub=$pub;signer=$signer}})")
def meta_worker():
    while True:
        b=[MQ.get()];time.sleep(.1)
        while not MQ.empty() and len(b)<60: b.append(MQ.get())
        try:
            r=subprocess.run(['powershell','-NoProfile','-Command',PS],input=json.dumps(b),capture_output=True,text=True,timeout=180,creationflags=0x08000000)
            d=json.loads(r.stdout or '[]');d=d if isinstance(d,list) else [d]
            for x in d:
                h=''
                if x.get('i'): h=hashlib.sha1(x['i'].encode()).hexdigest()[:12];ICONS.setdefault(h,x['i'])
                META[x['p'].lower()]=(x['s'],x['d'] or '',h,x.get('pub') or '',x.get('signer') or '')
        except Exception: pass
        for x in b: META.setdefault(x.lower(),('Unknown','','','',''))

RES={'rows':[],'partial':False,'ts':None,'yara':{}}
def scanner():
    while True:
        cur=[]
        try:
            if not RES['ts']: RES['rows']=cur   # first scan: show rows as they arrive
            part,yara_by_pid=scan(cur);RES.update(rows=cur,partial=part,ts=time.strftime('%Y-%m-%d %H:%M:%S'),yara=yara_by_pid)
        except Exception as e: print(e,file=sys.stderr)
        PROG['on']=False
        time.sleep(120)  # automated capture interval

def pusher():  # sends only deltas: progress, rows, icons, signatures
    sk=set();si=set();lr=lp=ly=None;sent_yara_info=False
    while True:
        try:
            if not sent_yara_info:
                emit({'t':'yara','rules':YARA_COUNT,'release':YARA_RELEASE,'error':YARA_ERROR,'pids':{}})
                sent_yara_info=True
            pg=(PROG['d'],PROG['t'],PROG['on'])
            if pg!=lp: lp=pg;emit({'t':'prog','dn':pg[0],'tot':pg[1],'on':pg[2]})
            rows=list(RES['rows']);rk=(RES['ts'],len(rows))
            if rows and rk!=lr: lr=rk;emit({'t':'rows','ts':RES['ts'],'partial':RES['partial'],'rows':rows})
            if RES['ts'] and RES['ts']!=ly:
                ly=RES['ts'];emit({'t':'yara','rules':YARA_COUNT,'release':YARA_RELEASE,'error':YARA_ERROR,'pids':RES['yara']})
            ni={h:ICONS[h] for h in list(ICONS) if h not in si}
            if ni: si.update(ni);emit({'t':'ico','map':ni})
            new={k:[v[0],v[2]] for k,v in list(META.items()) if k not in sk}
            if new: sk.update(new);emit({'t':'sig','m':new})
        except Exception as e: print(e,file=sys.stderr)
        time.sleep(1)

# ---- live process list + performance ----
def ticker():
    n=psutil.cpu_count() or 1;cpu_name=platform.processor()
    pd=psutil.disk_io_counters();pn=psutil.net_io_counters();t0=time.time();i=0;nproc=th=0
    psutil.cpu_percent(percpu=True)
    for p in psutil.process_iter():
        try: p.cpu_percent()
        except Exception: pass
    while True:
        time.sleep(1);now=time.time();dt=now-t0;t0=now
        if i%2==0:
            rows=[];th=0
            for p in psutil.process_iter(['pid','name','username','status','exe','num_threads','memory_info']):
                x=p.info;th+=x['num_threads'] or 0;ex=x['exe'] or '';mi=x['memory_info']
                try: cpu=p.cpu_percent()/n
                except Exception: cpu=0
                if ex: want(ex)
                meta=META.get(ex.lower(),('Unknown','','','',''))
                rows.append({'name':x['name'] or '','pid':x['pid'],'st':'Suspended' if x['status']=='stopped' else 'Running',
                    'user':(x['username'] or '').split('\\')[-1],'cpu':round(cpu,1),'mem':getattr(mi,'private',getattr(mi,'rss',0)) if mi else 0,
                    'arch':'x86' if '(x86)' in ex else 'x64','desc':meta[1],'exe':ex,'publisher':meta[3],
                    'sig':meta[0],'signer':meta[4],'ico':meta[2],
                    'yara':RES['yara'].get(str(x['pid']),{'status':'not-scanned','matches':[]})})
            nproc=len(rows);emit({'t':'det','rows':rows})
        c=psutil.cpu_percent(percpu=True);vm=psutil.virtual_memory();d=psutil.disk_io_counters();nt=psutil.net_io_counters()
        f=psutil.cpu_freq()
        emit({'t':'perf','cpu':sum(c)/len(c),'cores':c,'mem':[vm.used,vm.total,vm.available,vm.percent],
              'dr':(d.read_bytes-pd.read_bytes)/dt,'dw':(d.write_bytes-pd.write_bytes)/dt,
              'nu':(nt.bytes_sent-pn.bytes_sent)/dt,'nd':(nt.bytes_recv-pn.bytes_recv)/dt,
              'procs':nproc,'threads':th,'up':int(now-psutil.boot_time()),'mhz':f.current if f else 0,'name':cpu_name})
        pd,pn=d,nt;i+=1

if __name__=='__main__':
    for f in (scanner,pusher,ticker)+(meta_worker,)*6: threading.Thread(target=f,daemon=True).start()
    for line in sys.stdin:
        try:
            c=json.loads(line)
            if c['cmd']=='kill':
                p=psutil.Process(c['pid']);ps=[p]+(p.children(recursive=True) if c.get('tree') else [])
                for q in ps:
                    try: q.kill()
                    except Exception: pass
        except Exception: pass
