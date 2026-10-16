#!/usr/bin/env python3
"""Generate a deterministic, benign, two-VM reverse-engineering challenge.
Keep this generator and all instructor material out of the student handout.
"""
import hashlib
import json
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MASK = 0xffffffff
ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def rol(v, n):
    n &= 31
    return ((v << n) | (v >> ((32 - n) & 31))) & MASK


def ror(v, n):
    return rol(v, -n)


def chacha(key, nonce, data):
    def quarter(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & MASK; s[d] = rol(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & MASK; s[b] = rol(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & MASK; s[d] = rol(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & MASK; s[b] = rol(s[b] ^ s[c], 7)
    out = bytearray()
    for off in range(0, len(data), 64):
        initial = list(struct.unpack('<4I', b'expand 32-byte k'))
        initial += list(struct.unpack('<8I', key))
        initial += [1 + off // 64] + list(struct.unpack('<3I', nonce))
        state = initial.copy()
        for _ in range(10):
            for q in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                      (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
                quarter(state, *q)
        block = struct.pack('<16I', *((a+b)&MASK for a,b in zip(state, initial)))
        out.extend(a ^ b for a,b in zip(data[off:off+64], block))
    return bytes(out)


def fnv(data, seed=2166136261):
    for byte in data:
        seed = ((seed ^ byte) * 16777619) & MASK
    return seed


def derive(key, label):
    return hashlib.sha256(key + label).digest()


def split_root(key, rng):
    a = rng.randbytes(32)
    b = bytearray(32)
    for i in range(32):
        n = (i % 7) + 1
        v = key[i] ^ a[(i*7)&31] ^ ((i*29 + 0x63)&255)
        b[(i*13)&31] = ((v >> n) | (v << (8-n))) & 255
    return a, bytes(b)


def recover_root(a, b):
    return bytes((((b[(i*13)&31] << ((i%7)+1)) |
                  (b[(i*13)&31] >> (8-((i%7)+1)))) & 255)
                 ^ a[(i*7)&31] ^ ((i*29+0x63)&255) for i in range(32))


def permutation(rng, count):
    tokens = rng.sample(range(1, 255), count)
    table = [255]*256
    for kind, token in enumerate(tokens):
        table[token] = kind
    return tokens, bytes(table)


def execute_b(ops, ticket):
    regs = [0]*16
    mismatch = 0
    for op, a, b, imm in ops:
        if op == 0: regs[a] = struct.unpack_from('<I', ticket, imm)[0]
        elif op == 1: regs[a] = (regs[a]+regs[b]) & MASK
        elif op == 2: regs[a] ^= regs[b]
        elif op == 3: regs[a] = (regs[a]+imm) & MASK
        elif op == 4: regs[a] ^= imm
        elif op == 5: regs[a] = rol(regs[a], imm)
        elif op == 6: regs[a] = ror(regs[a], imm)
        elif op == 7: regs[a], regs[b] = regs[b], regs[a]
        elif op == 8: regs[a] = (regs[a]*imm) & MASK
        elif op == 9: regs[a] ^= regs[a] >> (imm&31)
        elif op == 10: mismatch |= regs[a] ^ imm
        elif op == 11: regs[a] = imm
        elif op == 12: pass
        elif op == 13: break
        else: raise ValueError(op)
    return regs, mismatch


def pack_b(ops, tokens, key, rng):
    out = bytearray()
    for pc, (op,a,b,imm) in enumerate(ops):
        encoded = struct.pack('<BBBBI', tokens[op], a ^ key[pc&31],
                              b ^ key[(pc+11)&31], rng.randrange(256),
                              rol(imm ^ struct.unpack_from('<I', key, (pc&7)*4)[0], (pc%31)+1))
        tag = fnv(encoded, 2166136261 ^ pc ^ struct.unpack_from('<I', key, (pc&7)*4)[0])
        out.extend(encoded + struct.pack('<I', tag))
    return bytes(out)


def main():
    # Reproducible instructor-only seed, not a credential or external secret.
    rng = random.Random('RF/VexedWolverine/20261005/v1')
    root_key, stage_key = rng.randbytes(32), rng.randbytes(32)
    answer = ''.join(rng.choice(ALPHABET) for _ in range(32)).encode()
    flag = ('VW{' + rng.randbytes(20).hex() + '}').encode()
    a, b = split_root(root_key, rng)
    assert recover_root(a,b) == root_key
    tok_a, map_a = permutation(rng, 10)
    tok_b, map_b = permutation(rng, 14)

    # Stack VM: PUSH, XOR, ADD, ROL8, OUT, DUP, SWAP, DROP, NOP, HALT.
    a_ops = []
    for i, wanted in enumerate(stage_key):
        x, y, z, n = rng.randrange(256), rng.randrange(256), rng.randrange(256), rng.randrange(1,8)
        v = ((x ^ y) + z) & 255
        v = ((v << n) | (v >> (8-n))) & 255
        a_ops += [(0,x),(0,y),(1,0),(0,z),(2,0),(3,n),
                  (5,0),(0,rng.randrange(256)),(1,0),(6,0),(6,0),(7,0),
                  (0,v ^ wanted),(1,0),(4,i),(8,0)]
    a_ops += [(9,0)]
    prog_a = bytearray()
    for pc,(op,arg) in enumerate(a_ops):
        filler = rng.randrange(256)
        prog_a.extend([tok_a[op], arg ^ root_key[pc&31] ^ ((pc*17)&255),
                       filler, (tok_a[op] ^ arg ^ filler ^ pc)&255])

    # Register VM: an invertible ARX/multiply/xorshift network, not a hash
    # preimage problem. Every real operation has a defined inverse.
    ops = [(0,i,0,i*4) for i in range(8)]
    for i in range(8): ops.append((4,i,0,rng.getrandbits(32)))
    for round_ in range(48):
        order = rng.sample(range(8),8)
        for i in range(0,8,2):
            x,y = order[i:i+2]
            ops += [(1,x,y,0), (4,x,0,rng.getrandbits(32)),
                    (5,x,0,rng.randrange(1,32)), (2,y,x,0),
                    (3,y,0,rng.getrandbits(32)), (6,y,0,rng.randrange(1,32)),
                    (8,x,0,rng.getrandbits(32)|1), (9,y,0,rng.randrange(1,32))]
            # Real VM instructions on non-output registers provide junk work.
            p,q = rng.sample(range(8,16),2)
            ops += [(11,p,0,rng.getrandbits(32)),(3,p,0,rng.getrandbits(32)),
                    (5,p,0,rng.randrange(1,32)),(2,q,p,0),(12,0,0,0)]
        x,y = rng.sample(range(8),2)
        ops.append((7,x,y,0))
    target,_ = execute_b(ops,answer)
    ops += [(10,i,0,target[i]) for i in rng.sample(range(8),8)]
    ops += [(13,0,0,0)]
    assert execute_b(ops,answer)[1] == 0
    assert execute_b(ops,b'A'*32)[1] != 0
    prog_b = pack_b(ops,tok_b,stage_key,rng)

    strings = [
        b'Vexed Wolverine / expert reserve challenge',
        b'Usage: vexedwolverine <32-character ticket>',
        b'No valid ticket. The attractive answer was a decoy.',
        b'VW{DEBUGGER_BRANCH_IS_NOT_THE_FLAG}',
        b'VW{TIMING_BRANCH_IS_NOT_THE_FLAG}',
        b'VW{PATCHING_A_BOOLEAN_IS_NOT_ENOUGH}',
        b'Container integrity mismatch.',
        b'/proc/self/status', b'TracerPid:', b'VW_LAB_MODE',
    ]
    plain_s = b'\0'.join(strings)+b'\0'
    offsets, cursor = [], 0
    for value in strings:
        offsets.append(cursor); cursor += len(value)+1
    nonce_a, nonce_b, nonce_s, nonce_f, nonce_root = (rng.randbytes(12) for _ in range(5))
    ea = chacha(derive(root_key,b'/a'),nonce_a,prog_a)
    eb = chacha(stage_key,nonce_b,prog_b)
    es = chacha(derive(root_key,b'/s'),nonce_s,plain_s)
    flag_key = hashlib.sha256(answer+stage_key+b'/f').digest()
    ef = chacha(flag_key,nonce_f,flag)
    plain = b'VWLAB01\0' + struct.pack('<4I',len(ea),len(eb),len(es),len(ef))
    plain += nonce_a+nonce_b+nonce_s+nonce_f+map_a+map_b
    plain += struct.pack('<10I',*offsets) + hashlib.sha256(flag).digest()
    plain += ea+eb+es+ef
    encrypted = chacha(root_key,nonce_root,plain)
    digest = hashlib.sha256(encrypted).digest()
    def c_array(name,data,qualifier='static const'):
        lines = [', '.join(f'0x{x:02x}' for x in data[i:i+16]) for i in range(0,len(data),16)]
        return f'{qualifier} uint8_t {name}[{len(data)}] = {{\n    ' + ',\n    '.join(lines) + '\n};\n'
    header = '/* Generated instructor material. Never include in the student handout. */\n'
    header += c_array('q_a',a,'static const volatile')
    header += c_array('q_b',b,'static const volatile')
    header += c_array('q_nonce',nonce_root)
    header += c_array('q_digest',digest)
    api_hash = 0
    for byte in b'IsDebuggerPresent': api_hash = (ror(api_hash,13)+byte)&MASK
    header += f'#define VW_DEBUG_API_HASH 0x{api_hash:08x}u\n'
    header += c_array('q_blob',encrypted,'static const VW_SECTION')
    (ROOT/'src/generated.h').write_text(header)
    packet = {'a':a.hex(),'b':b.hex(),'nonce':nonce_root.hex(),
              'digest':digest.hex(),'blob':encrypted.hex()}
    (ROOT/'instructor/container.json').write_text(json.dumps(packet,indent=2)+'\n')
    (ROOT/'instructor/answers.json').write_text(json.dumps({
        'ticket':answer.decode(),'flag':flag.decode(),
        'vm_a_instructions':len(a_ops),'vm_b_instructions':len(ops),
        'vm_b_real_registers':8,'rounds':48,
    },indent=2)+'\n')
    print(f'Generated {len(a_ops)} stack-VM and {len(ops)} register-VM instructions; {len(encrypted)} encrypted bytes.')


if __name__ == '__main__':
    main()
