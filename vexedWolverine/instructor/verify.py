#!/usr/bin/env python3
"""Meaningful local qualification of the author's own benign challenge."""
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from generate import chacha
from solve_offline import solve

ROOT=Path(__file__).resolve().parents[1]


def command(args, **kwargs):
    return subprocess.run(args,text=True,capture_output=True,timeout=20,**kwargs)


def main():
    answers=json.loads((ROOT/'instructor/answers.json').read_text())
    packet=json.loads((ROOT/'instructor/container.json').read_text())
    solved=solve(packet)
    assert solved['ticket']==answers['ticket'] and solved['flag']==answers['flag']
    binary=ROOT/'student/vexedWolverineLinux'
    def build_path(name): return ROOT/('instructor/dist' if name.endswith('.exe') else 'student')/name
    checks=[]
    def check(name, condition):
        assert condition,name
        checks.append(name)
    check('Independent VM inversion recovers the intended ticket and flag',True)
    # RFC 8439 section 2.3.2 block vector; stream counter starts at one.
    vector=bytes.fromhex('10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
                         'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e')
    nonce=bytes.fromhex('000000090000004a00000000')
    check('Python ChaCha20 matches RFC 8439 block vector',chacha(bytes(range(32)),nonce,bytes(64))==vector)
    env=os.environ.copy();env.pop('VW_LAB_MODE',None)
    for mode in ('normal','lab'):
        run_env=env.copy()
        if mode=='lab':run_env['VW_LAB_MODE']='1'
        r=command([str(binary),answers['ticket']],env=run_env)
        check('Correct ticket accepted in '+mode+' mode',r.returncode==0 and answers['flag'] in r.stdout)
    invalid=['A'*32,'B'*32,answers['ticket'][:-1],answers['ticket']+'A',
             answers['ticket'].lower(),'!'*32,'VW{RAW_STRINGS_ARE_NOT_A_SOLUTION}']
    for i in range(32):
        s=list(answers['ticket']);s[i]='A' if s[i]!='A' else 'B';invalid.append(''.join(s))
    for i,ticket in enumerate(invalid):
        r=command([str(binary),ticket],env=env)
        check(f'Invalid ticket case {i+1} rejected',r.returncode!=0 and answers['flag'] not in r.stdout)
    r=command([str(binary)],env=env)
    check('Missing input rejected without a crash',r.returncode==1 and 'Usage:' in r.stdout)
    raw=binary.read_bytes();blob=bytes.fromhex(packet['blob']);pos=raw.find(blob)
    check('Encrypted container found once in native ELF',pos>=0 and raw.find(blob,pos+1)<0)
    with tempfile.TemporaryDirectory(prefix='vw_verify_') as scratch:
        scratch=Path(scratch)
        damaged=bytearray(raw);damaged[pos+len(blob)//2]^=1
        path=scratch/'tampered';path.write_bytes(damaged);path.chmod(0o700)
        r=command([str(path),answers['ticket']],env=env)
        check('Encrypted-container tampering rejected',r.returncode!=0 and 'integrity mismatch' in r.stderr)
        forced=scratch/'forced'
        r=command(['gcc','-std=c11','-O2','-pthread','-DVW_INSTRUCTOR_FORCE_VALID',
                   str(ROOT/'src/vexedwolverine.c'),'-o',str(forced)])
        check('Instructor forced-validation test build compiled',r.returncode==0)
        r=command([str(forced),'A'*32],env=env)
        check('Forced validation does not decrypt the real flag for wrong input',
              r.returncode!=0 and answers['flag'] not in r.stdout and 'PATCHING_A_BOOLEAN' in r.stdout)
        crypto=scratch/'crypto'
        r=command(['gcc','-std=c11','-O2',str(ROOT/'instructor/crypto_check.c'),'-o',str(crypto)])
        check('Independent C crypto-check build compiled',r.returncode==0)
        r=command([str(crypto)]);lines=r.stdout.splitlines()
        check('C SHA-256 agrees with hashlib for abc and padding boundaries',
              r.returncode==0 and lines[:4]==[hashlib.sha256(p).hexdigest() for p in
                                            (b'abc',bytes(range(56)),bytes(range(64)),bytes(range(129)))])
        check('C ChaCha20 agrees with RFC 8439 block vector',lines[4]==vector.hex())
    for name in ('vexedWolverineLinux','vexedWolverineWindows.exe'):
        data=build_path(name).read_bytes()
        check(name+' contains neither the real ticket nor the real flag',
              answers['ticket'].encode() not in data and answers['flag'].encode() not in data)
        check(name+' hides its runtime message and proc-status path',
              b'No valid ticket.' not in data and b'/proc/self/status' not in data)
    imports_linux=command(['objdump','-T',str(binary)])
    imports_win=command(['objdump','-p',str(build_path('vexedWolverineWindows.exe'))])
    check('Import inspection tools completed',imports_linux.returncode==0 and imports_win.returncode==0)
    prohibited=re.compile(r'\b(socket|connect|sendto|recvfrom|execve|system|CreateProcess[AW]|'
                          r'WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|RegSetValueEx[AW])\b')
    check('Imports show none of the listed network/process-injection/persistence APIs',
          not prohibited.search(imports_linux.stdout+imports_win.stdout))
    result={'status':'passed','checks':checks,'check_count':len(checks),
            'linux_runtime':'tested','windows_runtime':'not tested; no Wine installed',
            'macos_build':'source support only; no macOS toolchain available',
            'recovered_vm_a_instructions':solved['vm_a_instructions'],
            'recovered_vm_b_instructions':solved['vm_b_instructions'],
            'binaries':{n:hashlib.sha256(build_path(n).read_bytes()).hexdigest()
                        for n in ('vexedWolverineLinux','vexedWolverineWindows.exe')}}
    (ROOT/'instructor/validation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'{len(checks)} checks passed. Linux runtime verified; Windows compiled only; macOS source only.')


if __name__=='__main__':main()
