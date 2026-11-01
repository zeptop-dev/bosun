package forward

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// This helper is a separate copy of the test executable inside the forwarding
// namespace. Commands exercise the real Manager and nft binary, not a copy of
// the renderer or a mocked installer. The helper is unreachable in normal use.
func TestNFTNamespaceRuntimeHelper(t *testing.T) {
	if os.Getenv("BOSUN_NFT_RUNTIME_HELPER") != "1" {
		t.Skip("private namespace helper")
	}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fixture DNS unavailable")
	}}
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Stop()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var rules []spec.Forward
		if err := json.Unmarshal(scanner.Bytes(), &rules); err != nil {
			t.Fatal(err)
		}
		before := m.nftApplied
		err := m.Apply(rules)
		if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": err == nil, "unchanged": m.nftApplied == before}); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTLinuxRuntimeTransactions(t *testing.T) {
	if os.Getenv("BOSUN_NFT_TEST") != "1" || runtime.GOOS != "linux" {
		t.Skip("set BOSUN_NFT_TEST=1 on isolated Linux")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-n", "python3", "-c", nftRuntimePython)
	cmd.Env = append(os.Environ(), "BOSUN_FORWARD_TEST_BINARY="+binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// If a failing command reaches the outer deadline, also reap its helper
	// process group. Successful runs terminate and wait for every child below.
	defer func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated runtime: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "runtime transactions passed") {
		t.Fatalf("missing completed acceptance: %s", out)
	}
	t.Log(string(out))
}

const nftRuntimePython = `
import json, os, select, subprocess as s, time
children=[]
def run(*args, **kw): return s.run(args,check=True,capture_output=True,text=True,timeout=8,**kw)
def ns(pid,*args,**kw): return run('nsenter','-t',str(pid),'-n',*args,**kw)
def start(args,**kw):
 p=s.Popen(args,**kw);children.append(p);return p
def response(p):
 if not select.select([p.stdout],[],[],8)[0]: raise RuntimeError('fixture response timeout')
 line=p.stdout.readline()
 if not line: raise RuntimeError('fixture exited before response')
 return json.loads(line)
def command(p,value):
 p.stdin.write(json.dumps(value)+'\n');p.stdin.flush();return response(p)
try:
 spaces=[start(['unshare','-n','sleep','120']) for _ in range(2)]
 time.sleep(.2)
 client,target=[p.pid for p in spaces]
 run('ip','link','set','lo','up')
 for peer,pid,net,local,remote in [('cl',client,1,'192.0.2.1','192.0.2.10'),('tg',target,2,'198.51.100.1','198.51.100.20')]:
  run('ip','link','add',peer,'type','veth','peer','name',peer+'p')
  run('ip','link','set',peer+'p','netns',str(pid))
  run('ip','addr','add',local+'/24','dev',peer)
  run('ip','-6','addr','add',f'2001:db8:{net}::1/64','dev',peer,'nodad')
  run('ip','link','set',peer,'up')
  ns(pid,'ip','link','set','lo','up');ns(pid,'ip','link','set',peer+'p','up')
  ns(pid,'ip','addr','add',remote+'/24','dev',peer+'p')
  ns(pid,'ip','-6','addr','add',f'2001:db8:{net}::20/64','dev',peer+'p','nodad')
  ns(pid,'ip','route','add','default','via',local)
  ns(pid,'ip','-6','route','add','default','via',f'2001:db8:{net}::1')
 server=r'''
import socket,threading,time
sockets=[]
def stream(c,mark):
 with c:
  while True:
   data=c.recv(64)
   if not data:return
   c.sendall(mark+data)
def serve(sock,udp,mark):
 while True:
  if udp:
   data,addr=sock.recvfrom(64);sock.sendto(mark+data,addr)
  else:
   c,_=sock.accept();threading.Thread(target=stream,args=(c,mark),daemon=True).start()
for family,addr in [(socket.AF_INET,'198.51.100.20'),(socket.AF_INET6,'2001:db8:2::20')]:
 for port,mark in [(1081,b'old:'),(1082,b'new:')]:
  for udp in [False,True]:
   sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
   sock.bind((addr,port))
   if not udp:sock.listen()
   sockets.append(sock);threading.Thread(target=serve,args=(sock,udp,mark),daemon=True).start()
print('{}',flush=True);time.sleep(120)
'''
 serverproc=start(['nsenter','-t',str(target),'-n','python3','-u','-c',server],stdout=s.PIPE,text=True)
 response(serverproc)
 helper=start([os.environ['BOSUN_FORWARD_TEST_BINARY'],'-test.run=^TestNFTNamespaceRuntimeHelper$','-test.timeout=2m'],env=dict(os.environ,BOSUN_NFT_RUNTIME_HELPER='1'),stdin=s.PIPE,stdout=s.PIPE,text=True)
 rules=[dict(tag='v4',listen='192.0.2.1',port=21081,protocol='both',target='198.51.100.20:1081',backend='nft'),dict(tag='v6',listen='2001:db8:1::1',port=21081,protocol='both',target='[2001:db8:2::20]:1081',backend='nft')]
 assert command(helper,rules)==dict(ok=True,unchanged=False)
 clientcode=r'''
import json,socket,sys
held=[]
def exchange(sock,prefix):
 sock.sendall(b'echo')
 answer=b''
 while len(answer)<len(prefix)+4:
  chunk=sock.recv(64)
  assert chunk,'unexpected EOF'
  answer+=chunk
 assert answer==prefix+b'echo',answer
for line in sys.stdin:
 command=json.loads(line)
 if command=='close':
  for sock in held:sock.close()
  held=[]
 elif command=='held':
  for sock in held:exchange(sock,b'old:')
 else:
  for family,addr in [(socket.AF_INET,'192.0.2.1'),(socket.AF_INET6,'2001:db8:1::1')]:
   for udp in [False,True]:
    sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.settimeout(2);sock.connect((addr,21081));exchange(sock,b'new:' if command=='new' else b'old:')
    if command=='hold':held.append(sock)
    else:sock.close()
 print('{"ok":true}',flush=True)
'''
 clientproc=start(['nsenter','-t',str(client),'-n','python3','-u','-c',clientcode],stdin=s.PIPE,stdout=s.PIPE,text=True)
 assert command(clientproc,'hold')['ok']
 before=run('nft','-s','list','table','inet','bosun_fwd').stdout
 broken=rules+[dict(tag='unresolved',listen='192.0.2.1',port=21082,protocol='udp',target='missing.example.invalid:1081',backend='nft')]
 assert command(helper,broken)==dict(ok=False,unchanged=True)
 assert run('nft','-s','list','table','inet','bosun_fwd').stdout==before
 assert command(clientproc,'held')['ok'] and command(clientproc,'old')['ok']
 changed=[dict(rule,target=rule['target'].replace(':1081',':1082')) for rule in rules]
 assert command(helper,changed)==dict(ok=True,unchanged=False)
 # An existing tuple may retain its NAT mapping. New source ports must use
 # the new target; never mistake a held UDP socket for a new selection.
 assert command(clientproc,'held')['ok'] and command(clientproc,'new')['ok']
 assert command(clientproc,'close')['ok']
 assert command(helper,[])==dict(ok=True,unchanged=False)
 assert s.run(['nft','list','table','inet','bosun_fwd'],capture_output=True,timeout=4).returncode!=0
 helper.stdin.close();helper.wait(timeout=8)
 assert helper.returncode==0
 print('runtime transactions passed: IPv4/IPv6 TCP/UDP; DNS failure kept table and traffic; old tuples retained old target; new tuples used new target; cleanup removed table')
finally:
 for p in reversed(children):
  if p.poll() is None:p.terminate()
 for p in children:
  try:p.wait(timeout=3)
  except s.TimeoutExpired:p.kill();p.wait(timeout=3)
`
