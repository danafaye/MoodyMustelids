#!/usr/bin/env python3
"""Independent solve from the embedded-container representation, not answers.json.
An analyst must first recover the split root key and encrypted blobs from Ghidra
or a memory capture. This instructor helper demonstrates reversibility.
"""
import hashlib
import json
import struct
from pathlib import Path
from generate import chacha, derive, fnv, recover_root, rol, ror, MASK, execute_b

ROOT = Path(__file__).resolve().parents[1]


def invert_shift(value, n):
    shift = n
    while shift < 32:
        value ^= value >> shift
        shift *= 2
    return value & MASK


def solve(packet=None):
    packet = packet or json.loads((ROOT/'instructor/container.json').read_text())
    root = recover_root(bytes.fromhex(packet['a']),bytes.fromhex(packet['b']))
    blob = bytes.fromhex(packet['blob'])
    assert hashlib.sha256(blob).hexdigest() == packet['digest']
    plain = chacha(root,bytes.fromhex(packet['nonce']),blob)
    assert plain[:8] == b'VWLAB01\0'
    na,nb,ns,nf = struct.unpack_from('<4I',plain,8)
    assert 656+na+nb+ns+nf == len(plain)
    nonce_a,nonce_b,nonce_s,nonce_f = (plain[i:i+12] for i in (24,36,48,60))
    map_a,map_b = plain[72:328],plain[328:584]
    ea=plain[656:656+na];eb=plain[656+na:656+na+nb]
    ef=plain[-nf:]
    pa=chacha(derive(root,b'/a'),nonce_a,ea)
    stack=[];seed=bytearray(32);seen=set()
    for pc in range(na//4):
        op,encoded,filler,tag = pa[pc*4:pc*4+4]
        arg=encoded ^ root[pc&31] ^ ((pc*17)&255)
        assert tag==(op^arg^filler^pc)&255
        kind=map_a[op]
        if kind==0: stack.append(arg)
        elif kind==1: b=stack.pop();stack[-1]^=b
        elif kind==2: b=stack.pop();stack[-1]=(stack[-1]+b)&255
        elif kind==3: v=stack[-1];n=arg&7;stack[-1]=((v<<n)|(v>>((8-n)&7)))&255
        elif kind==4: seed[arg]=stack.pop();seen.add(arg)
        elif kind==5: stack.append(stack[-1])
        elif kind==6: stack[-1],stack[-2]=stack[-2],stack[-1]
        elif kind==7: stack.pop()
        elif kind==8: pass
        elif kind==9: assert pc+1==na//4;break
        else: raise ValueError(kind)
    assert len(seen)==32 and not stack
    pb=chacha(bytes(seed),nonce_b,eb);ops=[];targets={}
    for pc in range(nb//12):
        row=pb[pc*12:pc*12+12]
        op,ea_,eb_,filler,encoded,tag=struct.unpack('<BBBBII',row)
        kw=struct.unpack_from('<I',seed,(pc&7)*4)[0]
        assert tag==fnv(row[:8],2166136261^pc^kw)
        kind=map_b[op];a=ea_^seed[pc&31];b=eb_^seed[(pc+11)&31]
        imm=ror(encoded,(pc%31)+1)^kw
        assert 0<=a<16 and 0<=b<16
        ops.append((kind,a,b,imm))
        if kind==10: targets[a]=imm
    assert set(targets)==set(range(8))
    regs=[targets.get(i,0) for i in range(16)]
    ticket=bytearray(32)
    for kind,a,b,imm in reversed(ops):
        if kind in (10,12,13) or a>=8: continue
        if kind==0:struct.pack_into('<I',ticket,imm,regs[a])
        elif kind==1:regs[a]=(regs[a]-regs[b])&MASK
        elif kind==2:regs[a]^=regs[b]
        elif kind==3:regs[a]=(regs[a]-imm)&MASK
        elif kind==4:regs[a]^=imm
        elif kind==5:regs[a]=ror(regs[a],imm)
        elif kind==6:regs[a]=rol(regs[a],imm)
        elif kind==7:regs[a],regs[b]=regs[b],regs[a]
        elif kind==8:regs[a]=(regs[a]*pow(imm,-1,1<<32))&MASK
        elif kind==9:regs[a]=invert_shift(regs[a],imm&31)
        else:raise ValueError(kind)
    assert execute_b(ops,bytes(ticket))[1]==0
    flag_key=hashlib.sha256(bytes(ticket)+bytes(seed)+b'/f').digest()
    flag=chacha(flag_key,nonce_f,ef)
    assert hashlib.sha256(flag).digest()==plain[624:656]
    return {'ticket':ticket.decode('ascii'),'flag':flag.decode('ascii'),
            'vm_a_instructions':na//4,'vm_b_instructions':nb//12}


if __name__=='__main__':
    print(json.dumps(solve(),indent=2))
