#!/usr/bin/env python3
"""Run ONLY inside a fresh user + network namespace:
unshare --user --map-root-user --net python3 tests/diagnose/fault_lab.py
No host network settings are changed. Requires ip, nsenter, tc, ethtool, ping.
"""
import json, os, pathlib, socket, subprocess, sys, tempfile, threading, time
ROOT=pathlib.Path(__file__).resolve().parents[2]
BIN=ROOT/'target/debug/examples/diagnose_probe'
assert os.geteuid()==0, 'run with unshare --user --map-root-user --net'
# Protect against mistakenly executing as real root in the host namespace.
assert pathlib.Path('/proc/self/uid_map').read_text().split()[1] != '0', 'isolated user namespace required'

def cmd(*args, ns=None, check=True):
    prefix=['nsenter','-t',str(ns),'-n'] if ns else []
    return subprocess.run(prefix+list(map(str,args)),check=check,capture_output=True,text=True)

def ip(*args, **kw): return cmd('ip',*args,**kw)

peer=subprocess.Popen(['unshare','--net','sleep','600'])
children=[]
results=[]
try:
    time.sleep(.2)
    ip('link','set','lo','up'); ip('link','set','lo','up',ns=peer.pid)
    ip('link','add','nw0','type','veth','peer','name','nw1')
    ip('link','set','nw1','netns',peer.pid)
    for iface, ns in [('nw0',None),('nw1',peer.pid)]:
        ip('link','set',iface,'up',ns=ns)
        cmd('ethtool','-K',iface,'tso','off','gso','off','gro','off',ns=ns)
    ip('addr','add','192.0.2.1/24','dev','nw0')
    for addr in ['192.0.2.2/24','192.0.2.3/24']: ip('addr','add',addr,'dev','nw1',ns=peer.pid)
    ip('-6','addr','add','2001:db8::1/64','dev','nw0','nodad')
    for addr in ['2001:db8::2/64','2001:db8::3/64']: ip('-6','addr','add',addr,'dev','nw1','nodad',ns=peer.pid)
    ip('-6','route','add','default','via','2001:db8::2','dev','nw0')
    server=r'''
import socket,threading,pathlib,time,sys
mode=pathlib.Path(sys.argv[1])
def serve(addr):
 s=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,socket.SOCK_STREAM)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind((addr,8080));s.listen(200)
 while True:
  c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
def handle(c):
 try:
  c.settimeout(5);request=c.recv(4096)
  if not request:return
  m=mode.read_text().strip()
  if m=='timeout':time.sleep(4);return
  if m=='portal':data=b'HTTP/1.1 302 Found\r\nLocation: http://login.invalid/private?token=secret\r\nContent-Length: 0\r\n\r\n'
  elif m=='error':data=b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n'
  elif m=='body':data=b'HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n'+b'x'*8192
  else:data=b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n'
  c.sendall(data)
 except OSError:pass
 finally:c.close()
for a in ['192.0.2.2','192.0.2.3','2001:db8::2','2001:db8::3']:threading.Thread(target=serve,args=(a,),daemon=True).start()
time.sleep(600)
'''
    with tempfile.TemporaryDirectory(prefix='nw-fault-') as tmp:
        mode=pathlib.Path(tmp)/'mode'; mode.write_text('healthy')
        config=pathlib.Path(tmp)/'config.json'
        config.write_text(json.dumps({'ipv6_pairs':[{'v4':'192.0.2.2:8080','v6':'[2001:db8::2]:8080'},{'v4':'192.0.2.3:8080','v6':'[2001:db8::3]:8080'}], 'portal_endpoints':[{'url':'http://192.0.2.2:8080/','expect_status':204},{'url':'http://192.0.2.3:8080/','expect_status':204}], 'pmtu_url':'http://192.0.2.2:8080/'}))
        srv=subprocess.Popen(['nsenter','-t',str(peer.pid),'-n','python3','-c',server,str(mode)])
        children.append(srv);time.sleep(.4)
        def check(name,rule,want):
            start=time.monotonic(); r=json.loads(cmd(BIN,rule,config).stdout)
            assert r['outcome']==want, (name,r)
            assert 'secret' not in json.dumps(r), (name,'redirect credential leak')
            results.append({'case':name,'outcome':r['outcome'],'seconds':round(time.monotonic()-start,3)})
            print(json.dumps(results[-1]),flush=True)
        check('ipv6 healthy','ipv6.broken','healthy')
        ip('-6','route','del','default')
        check('IPv4-only not applicable','ipv6.broken','not_applicable')
        ip('-6','route','add','default','via','2001:db8::2','dev','nw0')
        for addr in ['2001:db8::2/64','2001:db8::3/64']: ip('-6','addr','del',addr,'dev','nw1',ns=peer.pid)
        check('IPv6 broken with working IPv4','ipv6.broken','fault')
        # Secondary first: with promote_secondaries at 0, the default in a
        # fresh namespace on some kernels, deleting the primary takes the
        # secondary with it and the second delete fails.
        for addr in ['192.0.2.3/24','192.0.2.2/24']: ip('addr','del',addr,'dev','nw1',ns=peer.pid)
        check('both families down','ipv6.broken','inconclusive')
        for addr in ['192.0.2.2/24','192.0.2.3/24']: ip('addr','add',addr,'dev','nw1',ns=peer.pid)
        for addr in ['2001:db8::2/64','2001:db8::3/64']: ip('-6','addr','add',addr,'dev','nw1','nodad',ns=peer.pid)
        check('portal expected response','captive.portal','healthy')
        mode.write_text('portal');check('corroborated redirects','captive.portal','fault')
        mode.write_text('error');check('server errors not portal','captive.portal','inconclusive')
        mode.write_text('timeout');check('timeouts not portal','captive.portal','inconclusive')
        mode.write_text('body');check('normal large transfer','pmtu.blackhole','healthy')
        for iface,ns in [('nw0',None),('nw1',peer.pid)]:ip('link','set',iface,'mtu','1280',ns=ns)
        check('lower working MTU','pmtu.blackhole','healthy')
        for iface,ns in [('nw0',None),('nw1',peer.pid)]:ip('link','set',iface,'mtu','1500',ns=ns)
        def filter_size(ns,iface):
            cmd('tc','qdisc','add','dev',iface,'clsact',ns=ns)
            cmd('tc','filter','add','dev',iface,'egress','protocol','ip','pref','1','basic','match','meta(pkt_len gt 1000)','action','drop',ns=ns)
        filter_size(None,'nw0');filter_size(peer.pid,'nw1')
        check('large packets silently dropped','pmtu.blackhole','fault')
        for iface,ns in [('nw0',None),('nw1',peer.pid)]:cmd('tc','qdisc','del','dev',iface,'clsact',ns=ns)
        cmd('tc','qdisc','add','dev','nw0','clsact')
        cmd('tc','filter','add','dev','nw0','egress','protocol','ip','pref','1','u32','match','ip','protocol','1','0xff','action','drop')
        check('ICMP filtered, TCP healthy','pmtu.blackhole','healthy')
        mode.write_text('timeout');check('ICMP filtered and transfer fails','pmtu.blackhole','inconclusive')
        cmd('tc','qdisc','del','dev','nw0','clsact')
        srv.terminate();srv.wait()
        check('endpoint down','pmtu.blackhole','inconclusive')
        # Apply a socket-denying seccomp policy only to this probe process and
        # its ping child. This exercises a real permission error without host
        # capabilities or changing the host's ping-group policy.
        def deny_sockets():
            import ctypes,platform
            class Filter(ctypes.Structure):
                _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
            class Program(ctypes.Structure):
                _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
            number={'x86_64':41,'aarch64':198}[platform.machine()]
            filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,number),Filter(0x06,0,0,0x50001),Filter(0x06,0,0,0x7fff0000))
            prog=Program(4,filters);libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(prog),0,0):raise RuntimeError('seccomp setup failed')
        blocked=subprocess.run([str(BIN),'pmtu.blackhole',str(config)],preexec_fn=deny_sockets,capture_output=True,text=True,check=True)
        denied=json.loads(blocked.stdout)
        assert denied['outcome']=='permission_denied',denied
        results.append({'case':'ICMP capability denied','outcome':denied['outcome']});print(json.dumps(results[-1]),flush=True)
        # Real namespace counters: full minute, failed active handshakes.
        healthy=json.loads(cmd(BIN,'kernel').stdout)
        assert healthy['failures_per_minute'] is None
        proc=subprocess.Popen([str(BIN),'kernel','62'],stdout=subprocess.PIPE,text=True)
        time.sleep(1)
        for _ in range(61):
            for _ in range(2):
                try:socket.create_connection(('127.0.0.1',65534),.1)
                except OSError:pass
            time.sleep(1)
        measured=json.loads(proc.communicate(timeout=5)[0]); assert measured['failures_per_minute']>5, measured
        results.append({'case':'real failed handshakes over 62 seconds','rate':measured['failures_per_minute']}); print(json.dumps(results[-1]),flush=True)
        # Exhaust no host resources: 101-port range in this throwaway namespace.
        pathlib.Path('/proc/sys/net/ipv4/ip_local_port_range').write_text('40000 40100')
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',8081));listener.listen(100)
        def drain():
            for _ in range(75):
                c,_=listener.accept()
                while c.recv(4096):pass
                c.close()
        t=threading.Thread(target=drain);t.start()
        for port in range(40000,40075):
            c=socket.socket();c.bind(('127.0.0.1',port));c.connect(('127.0.0.1',8081));c.shutdown(socket.SHUT_WR)
            while c.recv(4096):pass
            c.close()
        t.join();listener.close()
        measured=json.loads(cmd(BIN,'kernel').stdout);assert measured['timewait_port_pct']>60,measured
        results.append({'case':'distinct TIME_WAIT ephemeral-port pressure','pct':measured['timewait_port_pct']});print(json.dumps(results[-1]),flush=True)
        print(json.dumps({'passed':len(results),'results':results}),flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate();p.wait()
    peer.terminate();peer.wait()
