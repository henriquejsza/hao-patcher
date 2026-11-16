"""Typed references in Swift's resolved value-witness layout bytecode.

ABI: swiftlang/swift stdlib/public/runtime/BytecodeLayouts.{h,cpp}.
Single-payload programs fall through; multi-payload branches have their own End.
Offsets and tag data are preserved verbatim, including packed four-byte fields.
"""
import struct

from .exports import Refusal, require


def references(blob):
    require(len(blob)>=24, 'truncated runtime layout string')
    flags,size=struct.unpack_from('<QQ',blob)
    require(flags==0 and size+24==len(blob), 'unsupported runtime layout string header')
    slots={}

    def word(at,end):
        require(0<=at and at+8<=end, 'truncated runtime layout operand')
        return struct.unpack_from('<Q',blob,at)[0]

    def pointer(at,end,executable=False,nullable=False):
        value=word(at,end)
        require(value or nullable, 'null runtime layout reference')
        if value:
            require(at not in slots or slots[at]==executable, 'conflicting runtime layout references')
            slots[at]=executable

    def program(pos,end,terminated,depth=0):
        require(depth<=128, 'runtime layout nesting exceeds supported depth')
        while pos<end:
            tag=word(pos,end)>>56; pos+=8
            if tag==0:
                require(terminated, 'unexpected End in runtime layout payload')
                return pos
            if 1<=tag<=11 or tag==14:
                continue
            if tag==12:
                pointer(pos,end); pos+=8
            elif tag in (16,18,19):
                if tag==16:
                    count=word(pos+32,end); pos+=48
                elif tag==18:
                    pointer(pos,end,True)
                    count=word(pos+8,end); pos+=24
                else:
                    pointer(pos+16,end,nullable=True)
                    count=word(pos+28,end); pos+=44
                require(pos+count<=end, 'runtime layout payload exceeds program')
                program(pos,pos+count,False,depth+1); pos+=count
            elif tag in (21,22):
                if tag==21:
                    pointer(pos,end,True)
                else:
                    require(word(pos,end) in (0,1,2,4), 'unsupported runtime enum tag width')
                count=word(pos+8,end); size=word(pos+16,end)
                word(pos+24,end); pos+=32
                start=pos+count*8; finish=start+size
                require(finish<=end, 'runtime layout branches exceed program')
                for i in range(count):
                    offset=word(pos+8*i,end)
                    require(offset<size, 'runtime layout branch offset outside payload')
                    program(start+offset,finish,True,depth+1)
                pos=finish
            else:
                raise Refusal(f'unsupported runtime layout string opcode {tag:#x}')
        require(not terminated, 'runtime layout string has no End')
        return pos

    require(program(16,len(blob),True)==len(blob), 'early End in runtime layout string')
    ordered=sorted(slots.items())
    require(all(a+8<=b for (a,_),(b,_) in zip(ordered,ordered[1:])), 'overlapping runtime layout references')
    return ordered
