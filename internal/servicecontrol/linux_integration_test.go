package servicecontrol

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"testing"

	"github.com/zeptop-dev/bosun/internal/forward"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// All network state and processes live under unshare -n. The fixture exercises
// real root relay SO_MARK sockets, non-root proxy sockets, established DNAT,
// foreign DNAT isolation, and a real kernel WireGuard tunnel forwarding boundary.
func TestServiceControlLinux(t *testing.T) {
	if os.Getenv("BOSUN_SERVICE_CONTROL_TEST") != "1" {
		t.Skip("set BOSUN_SERVICE_CONTROL_TEST=1 for isolated Linux service control integration")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-n", "python3", "-u", "-c", serviceControlLinuxPython)
	cmd.Env = append(os.Environ(), "CONTROL_TEST_BIN="+exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated service control: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestServiceControlLinuxHelper(t *testing.T) {
	if os.Getenv("BOSUN_CONTROL_HELPER") != "1" {
		t.Skip("isolated helper")
	}
	ctx := context.Background()
	f := forward.NewManager(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	defer f.Stop()
	f.SetServiceControl(true)
	rules := []spec.Forward{
		{Tag: "n4", Backend: "nft", Listen: "192.0.2.1", Port: 21081, Target: "198.51.100.20:1081", Protocol: "both"},
		{Tag: "n6", Backend: "nft", Listen: "2001:db8:1::1", Port: 21081, Target: "[2001:db8:2::20]:1081", Protocol: "both"},
		{Tag: "r4", Listen: "192.0.2.1", Port: 21082, Target: "198.51.100.20:1081", Protocol: "both"},
		{Tag: "r6", Listen: "2001:db8:1::1", Port: 21082, Target: "[2001:db8:2::20]:1081", Protocol: "both"},
	}
	scopes, err := f.ServiceControlScope(ctx, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Apply(rules); err != nil {
		t.Fatal(err)
	}
	ctl := Manager{Dir: t.TempDir()}
	scope := Scope{Forwards: scopes, Interfaces: []string{"bwg7"}}
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		mode := scanner.Text()
		if mode == "quit" {
			return
		}
		policy := &spec.ServiceControl{Revision: mode, Mode: mode}
		if mode == "limit" {
			policy.LimitMbps = 1
		}
		if err = ctl.Apply(ctx, policy, 65534, false, scope); err != nil {
			t.Fatal(err)
		}
		fmt.Println("applied", mode)
	}
}

const serviceControlLinuxPython = `
import os,subprocess as s,time,socket
children=[]
def run(*args,**kw):
 try:return s.run(args,check=True,capture_output=True,text=True,**kw)
 except s.CalledProcessError as e:
  print('command failed:',args,'stderr:',e.stderr,flush=True);raise
def ns(pid,*args,**kw):return run('nsenter','-t',str(pid),'-n',*args,**kw)
def child(*args,**kw):
 p=s.Popen(args,**kw);children.append(p);return p
try:
 client=child('unshare','-n','sleep','120').pid
 target=child('unshare','-n','sleep','120').pid
 wg=child('unshare','-n','sleep','120').pid
 time.sleep(.2)
 run('ip','link','set','lo','up')
 for dev,pid,net,local,remote in [('cl',client,1,'192.0.2.1','192.0.2.10'),('tg',target,2,'198.51.100.1','198.51.100.20'),('wt',wg,4,'203.0.113.1','203.0.113.10')]:
  run('ip','link','add',dev,'type','veth','peer','name',dev+'p');run('ip','link','set',dev+'p','netns',str(pid))
  run('ip','addr','add',local+'/24','dev',dev);run('ip','-6','addr','add',f'2001:db8:{net}::1/64','dev',dev,'nodad');run('ip','link','set',dev,'up')
  ns(pid,'ip','link','set','lo','up');ns(pid,'ip','link','set',dev+'p','up');ns(pid,'ip','addr','add',remote+'/24','dev',dev+'p');ns(pid,'ip','-6','addr','add',f'2001:db8:{net}::20/64','dev',dev+'p','nodad')
  ns(pid,'ip','route','add','default','via',local);ns(pid,'ip','-6','route','add','default','via',f'2001:db8:{net}::1')

 # Real WireGuard transport: the guard sees inner packets once at FORWARD,
 # while encrypted UDP and the management account remain independent.
 hostkey=run('wg','genkey').stdout.strip();peerkey=run('wg','genkey').stdout.strip()
 hostpub=run('wg','pubkey',input=hostkey+'\n').stdout.strip();peerpub=run('wg','pubkey',input=peerkey+'\n').stdout.strip()
 run('ip','link','add','bwg7','type','wireguard');ns(wg,'ip','link','add','bwg7','type','wireguard')
 run('wg','set','bwg7','private-key','/dev/stdin','listen-port','51821','peer',peerpub,'allowed-ips','10.10.0.2/32,2001:db8:3::20/128','endpoint','203.0.113.10:51822',input=hostkey+'\n')
 ns(wg,'wg','set','bwg7','private-key','/dev/stdin','listen-port','51822','peer',hostpub,'allowed-ips','0.0.0.0/0,::/0','endpoint','203.0.113.1:51821',input=peerkey+'\n')
 run('ip','addr','add','10.10.0.1/30','dev','bwg7');run('ip','-6','addr','add','2001:db8:3::1/64','dev','bwg7','nodad');run('ip','link','set','bwg7','up')
 ns(wg,'ip','addr','add','10.10.0.2/30','dev','bwg7');ns(wg,'ip','-6','addr','add','2001:db8:3::20/64','dev','bwg7','nodad');ns(wg,'ip','link','set','bwg7','up')
 ns(wg,'ip','route','add','198.51.100.0/24','dev','bwg7');ns(wg,'ip','-6','route','add','2001:db8:2::/64','dev','bwg7')
 run('sysctl','-q','-w','net.ipv4.ip_forward=1','net.ipv6.conf.all.forwarding=1')
 server=r'''
import socket,threading,time,os
if os.environ.get('CORE')=='1': os.setgid(65534);os.setuid(65534)
def serve(sock,udp):
 while True:
  if udp:
   data,addr=sock.recvfrom(65535);sock.sendto(data,addr)
  else:
   conn,_=sock.accept()
   def work(c):
    try:
     while True:
      data=c.recv(65535)
      if not data:break
      if data==b'bulk':
       chunk=b'x'*16384
       while True:c.sendall(chunk)
      else:c.sendall(data)
    except OSError:pass
    finally:c.close()
   threading.Thread(target=work,args=(conn,),daemon=True).start()
port=int(os.environ.get('PORT','1081'))
for family,addr in [(socket.AF_INET,os.environ.get('ADDR4','198.51.100.20')),(socket.AF_INET6,os.environ.get('ADDR6','2001:db8:2::20'))]:
 for udp in [False,True]:
  sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind((addr,port))
  if not udp:sock.listen()
  threading.Thread(target=serve,args=(sock,udp),daemon=True).start()
print('ready',flush=True);time.sleep(110)
'''
 p=child('nsenter','-t',str(target),'-n','python3','-u','-c',server,stdout=s.PIPE,text=True);assert p.stdout.readline().strip()=='ready'
 env=dict(os.environ,CORE='1',PORT='21083',ADDR4='192.0.2.1',ADDR6='2001:db8:1::1')
 p=child('python3','-u','-c',server,env=env,stdout=s.PIPE,text=True);assert p.stdout.readline().strip()=='ready'
 env=dict(os.environ,BOSUN_CONTROL_HELPER='1')
 helper=child(os.environ['CONTROL_TEST_BIN'],'-test.run','^TestServiceControlLinuxHelper$','-test.timeout','110s',env=env,stdin=s.PIPE,stdout=s.PIPE,text=True)
 assert helper.stdout.readline().strip()=='ready'
 def control(mode):
  helper.stdin.write(mode+'\n');helper.stdin.flush();line=helper.stdout.readline().strip()
  if line!='applied '+mode:
   helper.stdin.close();helper.wait(timeout=5);raise AssertionError(line+'\n'+helper.stdout.read())
 run('nft','-f','-',input='table inet foreign {\n chain pre {\n type nat hook prerouting priority -99; policy accept;\n ip daddr 192.0.2.1 tcp dport 21090 dnat ip to 198.51.100.20:1081\n }\n}\n')
 clientcode=r'''
import socket,sys,time,threading,json
kind=sys.argv[1];mode=sys.argv[2]
ports=[21081,21082,21083] if kind=='normal' else [1081]
addrs=[(socket.AF_INET,'192.0.2.1'),(socket.AF_INET6,'2001:db8:1::1')] if kind=='normal' else [(socket.AF_INET,'198.51.100.20'),(socket.AF_INET6,'2001:db8:2::20')]
if kind=='foreign':ports=[21090];addrs=[(socket.AF_INET,'192.0.2.1')]
if mode=='bulk':
 results=[];errors=[]
 def download(port):
  try:
   c=socket.socket();c.settimeout(3);c.connect(('192.0.2.1',port));c.sendall(b'bulk');c.settimeout(.2)
  except Exception as e:errors.append(str(e));return
  start=time.monotonic();n=0
  while time.monotonic()-start<4:
   try:n+=len(c.recv(65535))
   except socket.timeout:pass
  c.close();results.append(n)
 ts=[threading.Thread(target=download,args=(port,)) for port in ports]
 for t in ts:t.start()
 for t in ts:t.join()
 assert not errors,errors
 assert len(results)==len(ports),results
 print(json.dumps(results));sys.exit()
sockets=[]
for family,addr in addrs:
 for port in ports:
  for udp in [False,True] if kind!='foreign' else [False]:
   c=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);c.settimeout(.7);c.connect((addr,port));c.send(b'echo');assert c.recv(4)==b'echo';sockets.append(c)
if mode=='hold':
 print('ready',flush=True);sys.stdin.readline()
 for c in sockets:
  try:c.send(b'nope');data=c.recv(4)
  except (socket.timeout,ConnectionError):continue
  assert not data,'established managed flow survived pause'
 print('blocked',flush=True)
else:print('passed',kind)
'''
 def check(kind,pid): print(ns(pid,'python3','-c',clientcode,kind,'echo').stdout.strip())
 check('normal',client);check('wg',wg);check('foreign',client)
 holds=[]
 for kind,pid in [('normal',client),('wg',wg)]:
  p=child('nsenter','-t',str(pid),'-n','python3','-u','-c',clientcode,kind,'hold',stdin=s.PIPE,stdout=s.PIPE,text=True);assert p.stdout.readline().strip()=='ready';holds.append(p)
 control('pause')
 for p in holds:p.stdin.write('\n');p.stdin.flush();assert p.stdout.readline().strip()=='blocked';assert p.wait(timeout=15)==0
 check('foreign',client)
 # Unmarked root management remains reachable while every managed classifier drops.
 run('python3','-c',"import socket;s=socket.create_connection(('198.51.100.20',1081),2);s.sendall(b'root');assert s.recv(4)==b'root'")
 control('normal');check('normal',client);check('wg',wg)
 control('limit')
 result=ns(client,'python3','-c',clientcode,'normal','bulk').stdout.strip()
 import json
 counts=json.loads(result);total=sum(counts)
 assert len(counts)==3 and 0<total<800000,(counts,total) # one 1Mbps bucket + 64KiB burst for all three backends
 print('aggregate 1 Mbps bytes in 4s:',counts,total)
 # Deleting rules while retaining the table must be detected, not mistaken for applied.
 run('nft','flush','chain','inet','bosun_service_control','output')
 control('limit')
 rules=run('nft','list','chain','inet','bosun_service_control','output').stdout
 assert 'skuid 65534' in rules and 'goto controlled' in rules,rules
 control('normal');check('normal',client)
 helper.stdin.write('quit\n');helper.stdin.flush();assert helper.wait(timeout=10)==0
 print('dual-stack TCP/UDP; actual relay marks; core UID; established NAT and real WireGuard pause; foreign DNAT and root management; aggregate cap; tamper repair; resume passed')
finally:
 for p in reversed(children):
  if p.poll() is None:p.terminate()
 for p in children:
  try:p.wait(timeout=3)
  except s.TimeoutExpired:p.kill();p.wait()
`
