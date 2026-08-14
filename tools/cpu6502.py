"""Minimal but complete NMOS 6502 core (official opcodes) for running the
SMC sound engine offline. `cycles` is exact for the NMOS official set, including
the branch and indexed page-cross penalties; the 65C02 set reuses that table and
is approximate, since nothing clocks CPU2 against a frame.

CPU(...) is the NMOS core the card PRG needs.  CPU(..., cmos=True) switches to
the 65C02 set the CPU2 mask ROM needs: STZ/BRA/PHX/PLY, the (zp) modes, the
Rockwell bit ops (RMB/SMB/BBR/BBS), JMP (abs,X), and the CMOS behavior changes
(no JMP (abs) page-wrap bug, BIT immediate touches only Z)."""

class CPU:
    def __init__(self, mem_read, mem_write, cmos=False):
        self.r = mem_read
        self.w = mem_write
        self.a = self.x = self.y = 0
        self.sp = 0xFD
        self.pc = 0
        self.C=self.Z=self.I=self.D=self.B=self.V=self.N=0
        self.cycles = 0
        self.crossed = 0
        self.cmos = cmos
        self.ops = OPS_65C02 if cmos else OPS
        self.stopped = False        # set by STP; WAI also parks here

    # ---- flags helpers ----
    def setzn(self, v):
        v &= 0xFF
        self.Z = 1 if v == 0 else 0
        self.N = 1 if v & 0x80 else 0
        return v
    def p_get(self):
        return (self.C|(self.Z<<1)|(self.I<<2)|(self.D<<3)|(1<<5)|(self.V<<6)|(self.N<<7))|(self.B<<4)
    def p_set(self, v):
        self.C=v&1; self.Z=(v>>1)&1; self.I=(v>>2)&1; self.D=(v>>3)&1
        self.V=(v>>6)&1; self.N=(v>>7)&1

    def push(self,v): self.w(0x100|self.sp, v&0xFF); self.sp=(self.sp-1)&0xFF
    def pop(self): self.sp=(self.sp+1)&0xFF; return self.r(0x100|self.sp)

    def rd16(self,a): return self.r(a)|(self.r((a+1)&0xFFFF)<<8)
    def fetch(self):
        v=self.r(self.pc); self.pc=(self.pc+1)&0xFFFF; return v
    def fetch16(self):
        lo=self.fetch(); hi=self.fetch(); return lo|(hi<<8)

    # ---- addressing: return effective address ----
    def a_imm(self): a=self.pc; self.pc=(self.pc+1)&0xFFFF; return a
    def a_zp(self): return self.fetch()
    def a_zpx(self): return (self.fetch()+self.x)&0xFF
    def a_zpy(self): return (self.fetch()+self.y)&0xFF
    def a_abs(self): return self.fetch16()
    def a_absx(self):
        b=self.fetch16(); a=(b+self.x)&0xFFFF
        self.crossed=(b^a)>>8 & 1
        return a
    def a_absy(self):
        b=self.fetch16(); a=(b+self.y)&0xFFFF
        self.crossed=(b^a)>>8 & 1
        return a
    def a_indx(self):
        z=(self.fetch()+self.x)&0xFF
        return self.r(z)|(self.r((z+1)&0xFF)<<8)
    def a_indy(self):
        z=self.fetch()
        b=self.r(z)|(self.r((z+1)&0xFF)<<8); a=(b+self.y)&0xFFFF
        self.crossed=(b^a)>>8 & 1
        return a
    def a_ind(self):
        a=self.fetch16()
        if self.cmos:
            return self.r(a)|(self.r((a+1)&0xFFFF)<<8)
        lo=self.r(a); hi=self.r((a&0xFF00)|((a+1)&0xFF))  # 6502 page-wrap bug
        return lo|(hi<<8)
    def a_izp(self):                    # 65C02 (zp)
        z=self.fetch()
        return self.r(z)|(self.r((z+1)&0xFF)<<8)
    def a_iax(self):                    # 65C02 (abs,X)
        a=(self.fetch16()+self.x)&0xFFFF
        return self.r(a)|(self.r((a+1)&0xFFFF)<<8)

    def branch(self, cond):
        off=self.fetch()
        if cond:
            if off&0x80: off-=0x100
            base=self.pc
            self.pc=(self.pc+off)&0xFFFF
            self.cycles+=2 if (base^self.pc)&0xFF00 else 1

    def step(self):
        op=self.fetch()
        f=self.ops.get(op)
        if f is None:
            raise RuntimeError("unimpl opcode $%02X at $%04X"%(op,(self.pc-1)&0xFFFF))
        self.crossed=0
        self.cycles+=CYC[op]
        f(self)
        if self.crossed and op in CROSS_PENALTY:
            self.cycles+=1

    def nmi(self):
        """Take the NMI: the push the hardware does, B clear, then $FFFA."""
        self.push((self.pc>>8)&0xFF); self.push(self.pc&0xFF)
        self.push(self.p_get()&~0x10)
        self.I=1
        self.pc=self.rd16(0xFFFA)
        self.cycles+=7

    def run_subroutine(self, addr, max_steps=2_000_000):
        """Call addr like JSR; run until the matching RTS returns to a sentinel."""
        SENT=0x6FFD
        ret=(SENT-1)&0xFFFF          # RTS will pop this and add 1 -> SENT
        self.push((ret>>8)&0xFF); self.push(ret&0xFF)
        self.pc=addr
        n=0
        while self.pc!=SENT:
            self.step(); n+=1
            if n>max_steps:
                raise RuntimeError("runaway in subroutine at $%04X"%self.pc)

# NMOS base cycles, opcode by opcode; 2 stands in for everything unimplemented.
# Branches add their taken and page-cross cycles in branch(), and the reads
# below add one more when an indexed address crosses a page.
CYC=[
    7,6,2,2,2,3,5,2,3,2,2,2,2,4,6,2,   # $00
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $10
    6,6,2,2,3,3,5,2,4,2,2,2,4,4,6,2,   # $20
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $30
    6,6,2,2,2,3,5,2,3,2,2,2,3,4,6,2,   # $40
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $50
    6,6,2,2,2,3,5,2,4,2,2,2,5,4,6,2,   # $60
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $70
    2,6,2,2,3,3,3,2,2,2,2,2,4,4,4,2,   # $80
    2,6,2,2,4,4,4,2,2,5,2,2,2,5,2,2,   # $90
    2,6,2,2,3,3,3,2,2,2,2,2,4,4,4,2,   # $A0
    2,5,2,2,4,4,4,2,2,4,2,2,4,4,4,2,   # $B0
    2,6,2,2,3,3,5,2,2,2,2,2,4,4,6,2,   # $C0
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $D0
    2,6,2,2,3,3,5,2,2,2,2,2,4,4,6,2,   # $E0
    2,5,2,2,2,4,6,2,2,4,2,2,2,4,7,2,   # $F0
]
CROSS_PENALTY=frozenset((
    0x1D,0x19,0x11, 0x3D,0x39,0x31, 0x5D,0x59,0x51, 0x7D,0x79,0x71,
    0xBD,0xB9,0xB1,0xBC,0xBE, 0xDD,0xD9,0xD1, 0xFD,0xF9,0xF1,
))


# ---- opcode implementations ----
def _ld(reg):
    def f(c, addr_fn):
        v=c.r(addr_fn(c)); setattr(c,reg,c.setzn(v))
    return f

def build():
    O={}
    def op(code, fn): O[code]=fn

    # generic ALU using an address-mode function
    def make_load(reg, amode):
        def f(c):
            v=c.r(amode(c)); setattr(c,reg,c.setzn(v))
        return f
    def make_store(reg, amode):
        def f(c):
            c.w(amode(c), getattr(c,reg)&0xFF)
        return f

    am={'imm':CPU.a_imm,'zp':CPU.a_zp,'zpx':CPU.a_zpx,'zpy':CPU.a_zpy,
        'abs':CPU.a_abs,'absx':CPU.a_absx,'absy':CPU.a_absy,
        'indx':CPU.a_indx,'indy':CPU.a_indy}

    # LDA
    for code,mode in [(0xA9,'imm'),(0xA5,'zp'),(0xB5,'zpx'),(0xAD,'abs'),(0xBD,'absx'),(0xB9,'absy'),(0xA1,'indx'),(0xB1,'indy')]:
        op(code, make_load('a', am[mode]))
    # LDX
    for code,mode in [(0xA2,'imm'),(0xA6,'zp'),(0xB6,'zpy'),(0xAE,'abs'),(0xBE,'absy')]:
        op(code, make_load('x', am[mode]))
    # LDY
    for code,mode in [(0xA0,'imm'),(0xA4,'zp'),(0xB4,'zpx'),(0xAC,'abs'),(0xBC,'absx')]:
        op(code, make_load('y', am[mode]))
    # STA
    for code,mode in [(0x85,'zp'),(0x95,'zpx'),(0x8D,'abs'),(0x9D,'absx'),(0x99,'absy'),(0x81,'indx'),(0x91,'indy')]:
        op(code, make_store('a', am[mode]))
    # STX
    for code,mode in [(0x86,'zp'),(0x96,'zpy'),(0x8E,'abs')]:
        op(code, make_store('x', am[mode]))
    # STY
    for code,mode in [(0x84,'zp'),(0x94,'zpx'),(0x8C,'abs')]:
        op(code, make_store('y', am[mode]))

    # transfers
    op(0xAA, lambda c:(setattr(c,'x',c.setzn(c.a))))
    op(0xA8, lambda c:(setattr(c,'y',c.setzn(c.a))))
    op(0x8A, lambda c:(setattr(c,'a',c.setzn(c.x))))
    op(0x98, lambda c:(setattr(c,'a',c.setzn(c.y))))
    op(0xBA, lambda c:(setattr(c,'x',c.setzn(c.sp))))
    op(0x9A, lambda c:(setattr(c,'sp',c.x)))

    # stack
    op(0x48, lambda c:c.push(c.a))
    op(0x68, lambda c:setattr(c,'a',c.setzn(c.pop())))
    op(0x08, lambda c:c.push(c.p_get()|0x10))
    op(0x28, lambda c:c.p_set(c.pop()))

    # logical / arithmetic helpers operating on operand value
    def make_alu(amode, fn):
        def f(c):
            v=c.r(amode(c)); fn(c,v)
        return f
    def _ora(c,v): c.a=c.setzn(c.a|v)
    def _and(c,v): c.a=c.setzn(c.a&v)
    def _eor(c,v): c.a=c.setzn(c.a^v)
    def _adc(c,v):
        s=c.a+v+c.C
        c.V=1 if (~(c.a^v)&(c.a^s)&0x80) else 0
        c.C=1 if s>0xFF else 0
        c.a=c.setzn(s)
    def _sbc(c,v): _adc(c, v^0xFF)
    def _cmp_reg(reg):
        def g(c,v):
            r=getattr(c,reg); t=(r-v)&0x1FF
            c.C=1 if r>=v else 0; c.setzn(t&0xFF)
        return g
    def _bit(c,v):
        c.Z=1 if (c.a&v)==0 else 0; c.N=(v>>7)&1; c.V=(v>>6)&1

    for code,mode in [(0x09,'imm'),(0x05,'zp'),(0x15,'zpx'),(0x0D,'abs'),(0x1D,'absx'),(0x19,'absy'),(0x01,'indx'),(0x11,'indy')]:
        op(code, make_alu(am[mode], _ora))
    for code,mode in [(0x29,'imm'),(0x25,'zp'),(0x35,'zpx'),(0x2D,'abs'),(0x3D,'absx'),(0x39,'absy'),(0x21,'indx'),(0x31,'indy')]:
        op(code, make_alu(am[mode], _and))
    for code,mode in [(0x49,'imm'),(0x45,'zp'),(0x55,'zpx'),(0x4D,'abs'),(0x5D,'absx'),(0x59,'absy'),(0x41,'indx'),(0x51,'indy')]:
        op(code, make_alu(am[mode], _eor))
    for code,mode in [(0x69,'imm'),(0x65,'zp'),(0x75,'zpx'),(0x6D,'abs'),(0x7D,'absx'),(0x79,'absy'),(0x61,'indx'),(0x71,'indy')]:
        op(code, make_alu(am[mode], _adc))
    for code,mode in [(0xE9,'imm'),(0xE5,'zp'),(0xF5,'zpx'),(0xED,'abs'),(0xFD,'absx'),(0xF9,'absy'),(0xE1,'indx'),(0xF1,'indy')]:
        op(code, make_alu(am[mode], _sbc))
    for code,mode in [(0xC9,'imm'),(0xC5,'zp'),(0xD5,'zpx'),(0xCD,'abs'),(0xDD,'absx'),(0xD9,'absy'),(0xC1,'indx'),(0xD1,'indy')]:
        op(code, make_alu(am[mode], _cmp_reg('a')))
    for code,mode in [(0xE0,'imm'),(0xE4,'zp'),(0xEC,'abs')]:
        op(code, make_alu(am[mode], _cmp_reg('x')))
    for code,mode in [(0xC0,'imm'),(0xC4,'zp'),(0xCC,'abs')]:
        op(code, make_alu(am[mode], _cmp_reg('y')))
    for code,mode in [(0x24,'zp'),(0x2C,'abs')]:
        op(code, make_alu(am[mode], _bit))

    # INC/DEC memory
    def make_rmw(amode, fn):
        def f(c):
            a=amode(c); v=c.r(a); v=fn(c,v); c.w(a,v&0xFF)
        return f
    def _inc(c,v): return c.setzn(v+1)
    def _dec(c,v): return c.setzn(v-1)
    def _asl(c,v): c.C=(v>>7)&1; return c.setzn((v<<1)&0xFF)
    def _lsr(c,v): c.C=v&1; return c.setzn(v>>1)
    def _rol(c,v): nc=(v>>7)&1; r=((v<<1)|c.C)&0xFF; c.C=nc; return c.setzn(r)
    def _ror(c,v): nc=v&1; r=((v>>1)|(c.C<<7))&0xFF; c.C=nc; return c.setzn(r)
    for code,mode in [(0xE6,'zp'),(0xF6,'zpx'),(0xEE,'abs'),(0xFE,'absx')]:
        op(code, make_rmw(am[mode], _inc))
    for code,mode in [(0xC6,'zp'),(0xD6,'zpx'),(0xCE,'abs'),(0xDE,'absx')]:
        op(code, make_rmw(am[mode], _dec))
    for code,mode in [(0x06,'zp'),(0x16,'zpx'),(0x0E,'abs'),(0x1E,'absx')]:
        op(code, make_rmw(am[mode], _asl))
    for code,mode in [(0x46,'zp'),(0x56,'zpx'),(0x4E,'abs'),(0x5E,'absx')]:
        op(code, make_rmw(am[mode], _lsr))
    for code,mode in [(0x26,'zp'),(0x36,'zpx'),(0x2E,'abs'),(0x3E,'absx')]:
        op(code, make_rmw(am[mode], _rol))
    for code,mode in [(0x66,'zp'),(0x76,'zpx'),(0x6E,'abs'),(0x7E,'absx')]:
        op(code, make_rmw(am[mode], _ror))
    # accumulator shifts
    op(0x0A, lambda c:setattr(c,'a',_asl(c,c.a)))
    op(0x4A, lambda c:setattr(c,'a',_lsr(c,c.a)))
    op(0x2A, lambda c:setattr(c,'a',_rol(c,c.a)))
    op(0x6A, lambda c:setattr(c,'a',_ror(c,c.a)))

    # INX/DEX/INY/DEY
    op(0xE8, lambda c:setattr(c,'x',c.setzn(c.x+1)))
    op(0xCA, lambda c:setattr(c,'x',c.setzn(c.x-1)))
    op(0xC8, lambda c:setattr(c,'y',c.setzn(c.y+1)))
    op(0x88, lambda c:setattr(c,'y',c.setzn(c.y-1)))

    # flags
    op(0x18, lambda c:setattr(c,'C',0)); op(0x38, lambda c:setattr(c,'C',1))
    op(0x58, lambda c:setattr(c,'I',0)); op(0x78, lambda c:setattr(c,'I',1))
    op(0xB8, lambda c:setattr(c,'V',0))
    op(0xD8, lambda c:setattr(c,'D',0)); op(0xF8, lambda c:setattr(c,'D',1))

    # branches
    op(0x10, lambda c:c.branch(c.N==0)); op(0x30, lambda c:c.branch(c.N==1))
    op(0x50, lambda c:c.branch(c.V==0)); op(0x70, lambda c:c.branch(c.V==1))
    op(0x90, lambda c:c.branch(c.C==0)); op(0xB0, lambda c:c.branch(c.C==1))
    op(0xD0, lambda c:c.branch(c.Z==0)); op(0xF0, lambda c:c.branch(c.Z==1))

    # jumps / subroutines
    def _jmp(c): c.pc=c.a_abs(c)
    op(0x4C, lambda c:setattr(c,'pc',c.a_abs()))
    op(0x6C, lambda c:setattr(c,'pc',c.a_ind()))
    def _jsr(c):
        a=c.fetch16(); ret=(c.pc-1)&0xFFFF
        c.push((ret>>8)&0xFF); c.push(ret&0xFF); c.pc=a
    op(0x20, _jsr)
    def _rts(c):
        lo=c.pop(); hi=c.pop(); c.pc=((lo|(hi<<8))+1)&0xFFFF
    op(0x60, _rts)
    def _rti(c):
        c.p_set(c.pop()); lo=c.pop(); hi=c.pop(); c.pc=lo|(hi<<8)
    op(0x40, _rti)

    op(0xEA, lambda c:None)  # NOP
    return O

OPS=build()


def build_65c02():
    """The NMOS table plus every 65C02 opcode the RF5A18 mask ROM actually uses.

    Behavior differences from NMOS that matter here are handled on CPU itself
    (a_ind has no page-wrap bug when cmos is set); the rest is new opcodes.
    """
    O = dict(OPS)
    def op(code, fn): O[code] = fn

    am={'imm':CPU.a_imm,'zp':CPU.a_zp,'zpx':CPU.a_zpx,'zpy':CPU.a_zpy,
        'abs':CPU.a_abs,'absx':CPU.a_absx,'absy':CPU.a_absy,
        'indx':CPU.a_indx,'indy':CPU.a_indy,'izp':CPU.a_izp}

    # (zp) — the zero-page indirect mode NMOS lacks
    def alu(amode, fn):
        def f(c):
            fn(c, c.r(amode(c)))
        return f
    def _ora(c,v): c.a=c.setzn(c.a|v)
    def _and(c,v): c.a=c.setzn(c.a&v)
    def _eor(c,v): c.a=c.setzn(c.a^v)
    def _adc(c,v):
        s=c.a+v+c.C
        c.V=1 if (~(c.a^v)&(c.a^s)&0x80) else 0
        c.C=1 if s>0xFF else 0
        c.a=c.setzn(s)
    def _sbc(c,v): _adc(c, v^0xFF)
    def _cmp(c,v):
        c.C=1 if c.a>=v else 0; c.setzn((c.a-v)&0xFF)
    op(0x12, alu(am['izp'], _ora)); op(0x32, alu(am['izp'], _and))
    op(0x52, alu(am['izp'], _eor)); op(0x72, alu(am['izp'], _adc))
    op(0xB2, alu(am['izp'], lambda c,v: setattr(c,'a',c.setzn(v))))
    op(0xD2, alu(am['izp'], _cmp)); op(0xF2, alu(am['izp'], _sbc))
    op(0x92, lambda c: c.w(c.a_izp(), c.a & 0xFF))

    # STZ
    for code, mode in [(0x64,'zp'),(0x74,'zpx'),(0x9C,'abs'),(0x9E,'absx')]:
        op(code, (lambda m: lambda c: c.w(m(c), 0))(am[mode]))

    # BRA, INC A / DEC A, stack ops on X and Y
    op(0x80, lambda c: c.branch(True))
    op(0x1A, lambda c: setattr(c,'a',c.setzn(c.a+1)))
    op(0x3A, lambda c: setattr(c,'a',c.setzn(c.a-1)))
    op(0xDA, lambda c: c.push(c.x))
    op(0xFA, lambda c: setattr(c,'x',c.setzn(c.pop())))
    op(0x5A, lambda c: c.push(c.y))
    op(0x7A, lambda c: setattr(c,'y',c.setzn(c.pop())))

    # BIT: new modes.  Immediate sets only Z — it does NOT touch N or V, which
    # is why a BIT #$xx cannot be used to sample a status bit.
    def _bit(c,v):
        c.Z=1 if (c.a&v)==0 else 0; c.N=(v>>7)&1; c.V=(v>>6)&1
    op(0x34, alu(am['zpx'], _bit)); op(0x3C, alu(am['absx'], _bit))
    op(0x89, alu(am['imm'], lambda c,v: setattr(c,'Z',1 if (c.a&v)==0 else 0)))

    # TRB / TSB
    def rmw(amode, fn):
        def f(c):
            a=amode(c); c.w(a, fn(c, c.r(a)) & 0xFF)
        return f
    def _trb(c,v): c.Z=1 if (c.a&v)==0 else 0; return v & ~c.a
    def _tsb(c,v): c.Z=1 if (c.a&v)==0 else 0; return v | c.a
    op(0x14, rmw(am['zp'], _trb)); op(0x1C, rmw(am['abs'], _trb))
    op(0x04, rmw(am['zp'], _tsb)); op(0x0C, rmw(am['abs'], _tsb))

    op(0x7C, lambda c: setattr(c,'pc',c.a_iax()))

    # Rockwell bit ops.  RMB/SMB are read-modify-write on zero page; BBR/BBS
    # take a zero-page address AND a relative offset, so the operand is 2 bytes.
    for i in range(8):
        bit = 1 << i
        op(0x07 + i*0x10, (lambda b: rmw(CPU.a_zp, lambda c,v,b=b: v & ~b))(bit))
        op(0x87 + i*0x10, (lambda b: rmw(CPU.a_zp, lambda c,v,b=b: v | b))(bit))
        def bbr(c, b=bit):
            v = c.r(c.fetch()); c.branch((v & b) == 0)
        def bbs(c, b=bit):
            v = c.r(c.fetch()); c.branch((v & b) != 0)
        op(0x0F + i*0x10, bbr)
        op(0x8F + i*0x10, bbs)

    def _stp(c): c.stopped = True
    op(0xDB, _stp)
    op(0xCB, _stp)      # WAI: with no IRQ model, parking is the honest behavior
    return O


OPS_65C02 = build_65c02()
