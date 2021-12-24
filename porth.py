#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
from os import path
from typing import *
from enum import IntEnum, Enum, auto
from dataclasses import dataclass, field
from copy import copy
from time import sleep
import traceback

PORTH_EXT = '.porth'
X86_64_RET_STACK_CAP=8192
# TODO: INCLUDE_LIMIT should be probably customizable
INCLUDE_LIMIT=100

debug=False

Loc=Tuple[str, int, int]

class Keyword(Enum):
    IF=auto()
    IFSTAR=auto()
    ELSE=auto()
    END=auto()
    WHILE=auto()
    DO=auto()
    INCLUDE=auto()
    MEMORY=auto()
    PROC=auto()
    CONST=auto()
    OFFSET=auto()
    RESET=auto()
    ASSERT=auto()
    IN=auto()
    BIKESHEDDER=auto()
    INLINE=auto()

class DataType(IntEnum):
    INT=auto()
    BOOL=auto()
    PTR=auto()

assert len(DataType) == 3, "Exhaustive data type definition"
DATATYPE_BY_NAME: Dict[str, DataType] = {
    "int" : DataType.INT ,
    "bool": DataType.BOOL,
    "ptr" : DataType.PTR ,
}
DATATYPE_NAMES: Dict[DataType, str] = {v: k for k, v in DATATYPE_BY_NAME.items()}

assert len(DataType) == 3, 'Exhaustive casts for all data types'
class Intrinsic(Enum):
    PLUS=auto()
    MINUS=auto()
    MUL=auto()
    # TODO: split divmod intrinsic into div and mod back
    # It was never useful
    DIVMOD=auto()
    MAX=auto()
    EQ=auto()
    GT=auto()
    LT=auto()
    GE=auto()
    LE=auto()
    NE=auto()
    SHR=auto()
    SHL=auto()
    OR=auto()
    AND=auto()
    NOT=auto()
    PRINT=auto()
    DUP=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    ROT=auto()
    LOAD8=auto()
    STORE8=auto()
    LOAD16=auto()
    STORE16=auto()
    LOAD32=auto()
    STORE32=auto()
    LOAD64=auto()
    STORE64=auto()
    CAST_PTR=auto()
    CAST_INT=auto()
    CAST_BOOL=auto()
    ARGC=auto()
    ARGV=auto()
    ENVP=auto()
    HERE=auto()
    SYSCALL0=auto()
    SYSCALL1=auto()
    SYSCALL2=auto()
    SYSCALL3=auto()
    SYSCALL4=auto()
    SYSCALL5=auto()
    SYSCALL6=auto()
    STOP=auto()

# TODO: make conditional and unconditional jumps jump by relative address
# This will make the code more relocatable which will make it easily inlinable
class OpType(Enum):
    PUSH_INT=auto()
    PUSH_PTR=auto()
    PUSH_BOOL=auto()
    PUSH_STR=auto()
    PUSH_CSTR=auto()
    PUSH_MEM=auto()
    PUSH_LOCAL_MEM=auto()
    INTRINSIC=auto()
    IF=auto()
    IFSTAR=auto()
    ELSE=auto()
    END=auto()
    WHILE=auto()
    DO=auto()
    SKIP_PROC=auto()
    PREP_PROC=auto()
    RET=auto()
    CALL=auto()

class TokenType(Enum):
    WORD=auto()
    INT=auto()
    STR=auto()
    CSTR=auto()
    CHAR=auto()
    KEYWORD=auto()

assert len(TokenType) == 6, "Exhaustive Token type definition. The `value` field of the Token dataclass may require an update"
@dataclass
class Token:
    typ: TokenType
    text: str
    loc: Loc
    value: Union[int, str, Keyword]

OpAddr=int
MemAddr=int

@dataclass
class Op:
    typ: OpType
    token: Token
    operand: Optional[Union[int, str, Intrinsic, OpAddr]] = None

@dataclass
class Program:
    ops: List[Op] = field(default_factory=list)
    memory_capacity: int = 0

def compiler_diagnostic(loc: Loc, tag: str, message: str):
    print("%s:%d:%d: %s: %s" % (loc + (tag, message)), file=sys.stderr)

def compiler_error(loc: Loc, message: str):
    compiler_diagnostic(loc, 'ERROR', message)

def compiler_note(loc: Loc, message: str):
    compiler_diagnostic(loc, 'NOTE', message)

def not_enough_arguments(op: Op):
    assert len(OpType) == 18, f"Exhaustive handling of Op types in not_enough_arguments() (expected {len(OpType)}). Keep in mind that not all of the ops should be handled in here. Only those that consume elements from the stack."
    if op.typ == OpType.INTRINSIC:
        assert isinstance(op.operand, Intrinsic)
        compiler_error(op.token.loc, "not enough arguments for the `%s` intrinsic" % INTRINSIC_NAMES[op.operand])
    elif op.typ == OpType.DO:
        compiler_error(op.token.loc, "not enough arguments for the do-block")
    else:
        assert False, "unsupported type of operation"

DataStack=List[Tuple[DataType, Loc]]

@dataclass
class Context:
    stack: DataStack
    ip: OpAddr
    outs: List[Tuple[DataType, Loc]]

@dataclass
class Contract:
    ins: Sequence[Tuple[DataType, Loc]]
    outs: Sequence[Tuple[DataType, Loc]]

def type_check_contract(intro_token: Token, ctx: Context, contract: Contract):
    ins = list(contract.ins)
    stack = copy(ctx.stack)
    arg_count = 0
    while len(stack) > 0 and len(ins) > 0:
        actual, actual_loc = stack.pop()
        expected, expected_loc = ins.pop()
        if actual != expected:
            compiler_error(intro_token.loc, f"Argument {arg_count} of `{intro_token.text}` is expected to be type `{DATATYPE_NAMES[expected]}` but got type `{DATATYPE_NAMES[actual]}`")
            compiler_note(actual_loc, f"Argument {arg_count} was provided here")
            compiler_note(expected_loc, f"Expected type was declared here")
            exit(1)
        arg_count += 1

    if len(stack) < len(ins):
        compiler_error(intro_token.loc, f"Not enough arguments provided for `{intro_token.value}`. Expected {len(contract.ins)} but got {arg_count}.");
        compiler_note(intro_token.loc, f"Not provided arguments:")
        while len(ins) > 0:
            typ, loc = ins.pop()
            compiler_note(loc, f"`{DATATYPE_NAMES[typ]}`")
        exit(1)

    for typ, loc in contract.outs:
        stack.append((typ, intro_token.loc))
    ctx.stack = stack

def type_check_context_outs(ctx: Context):
    while len(ctx.stack) > 0 and len(ctx.outs) > 0:
        actual_typ, actual_loc = ctx.stack.pop()
        expected_typ, expected_loc = ctx.outs.pop()
        if expected_typ != actual_typ:
            compiler_error(actual_loc, f"Unexpected type `{DATATYPE_NAMES[actual_typ]}` on the stack")
            compiler_note(expected_loc, f"Expected type `{DATATYPE_NAMES[expected_typ]}`")
            exit(1)
    if len(ctx.stack) > len(ctx.outs):
        top_typ, top_loc = ctx.stack.pop()
        compiler_error(top_loc, f"Unhandled data on the stack:")
        compiler_note(top_loc, f"type `{DATATYPE_NAMES[top_typ]}`")
        while len(ctx.stack) > 0:
            typ, loc = ctx.stack.pop()
            compiler_note(loc, f"type `{DATATYPE_NAMES[typ]}`")
        exit(1)
    elif len(ctx.stack) < len(ctx.outs):
        top_typ, top_loc = ctx.outs.pop()
        compiler_error(top_loc, f"Insufficient data on the stack. Expected:")
        compiler_note(top_loc, f"type `{DATATYPE_NAMES[top_typ]}`")
        while len(ctx.outs) > 0:
            typ, loc = ctx.outs.pop()
            compiler_note(loc, f"and type `{DATATYPE_NAMES[typ]}`")
        exit(1)

def expect_arity(ctx: Context, op: Op, n: int) -> List[Tuple[DataType, Loc]]:
    if len(ctx.stack) < n:
        compiler_error(op.token.loc, f"Not enough arguments provided for `{op.token.value}`. Expected {n} but got {len(ctx.stack)}.");
        exit(1)
    return ctx.stack[-n:]

def type_check_program(program: Program, proc_contracts: Dict[OpAddr, Contract]):
    visited_dos: Dict[OpAddr, DataStack] = {}
    contexts: List[Context] = [Context(stack=[], ip=0, outs=[])]
    for proc_addr, proc_contract in reversed(list(proc_contracts.items())):
        contexts.append(Context(
            stack=list(proc_contract.ins),
            ip=proc_addr,
            outs=list(proc_contract.outs)
        ))
    while len(contexts) > 0:
        ctx = contexts[-1];
        if ctx.ip >= len(program.ops):
            type_check_context_outs(ctx)
            contexts.pop()
            continue
        op = program.ops[ctx.ip]
        assert len(OpType) == 18, "Exhaustive ops handling in type_check_program()"
        if op.typ == OpType.PUSH_INT:
            ctx.stack.append((DataType.INT, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_BOOL:
            ctx.stack.append((DataType.BOOL, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_PTR:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_STR:
            ctx.stack.append((DataType.INT, op.token.loc))
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_CSTR:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_MEM:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_LOCAL_MEM:
            ctx.stack.append((DataType.PTR, op.token.loc))
            ctx.ip += 1
        elif op.typ == OpType.SKIP_PROC:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.PREP_PROC:
            ctx.ip += 1
        elif op.typ == OpType.CALL:
            assert isinstance(op.operand, OpAddr)
            type_check_contract(op.token, ctx, proc_contracts[op.operand])
            ctx.ip += 1
        elif op.typ == OpType.RET:
            type_check_context_outs(ctx)
            contexts.pop()
        elif op.typ == OpType.INTRINSIC:
            assert len(Intrinsic) == 45, "Exhaustive intrinsic handling in type_check_program()"
            assert isinstance(op.operand, Intrinsic), "This could be a bug in compilation step"
            if op.operand == Intrinsic.PLUS:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.MINUS:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.MUL:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.DIVMOD:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.MAX:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.EQ:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.GT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.LT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.GE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.LE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.NE:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.SHR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SHL:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.OR:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.AND:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc), (DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.NOT:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.PRINT:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[]))
            elif op.operand == Intrinsic.DUP:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[a, a]))
            elif op.operand == Intrinsic.SWAP:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, b], outs=[b, a]))
            elif op.operand == Intrinsic.DROP:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[]))
            elif op.operand == Intrinsic.OVER:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, b], outs=[a, b, a]))
            elif op.operand == Intrinsic.ROT:
                [a, b, c] = expect_arity(ctx, op, 3)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, c], outs=[b, c, a]))
            elif op.operand == Intrinsic.LOAD8:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.STORE8:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, (DataType.PTR, b[1])], outs=[]))
            elif op.operand == Intrinsic.LOAD16:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.STORE16:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, (DataType.PTR, b[1])], outs=[]))
            elif op.operand == Intrinsic.LOAD32:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.STORE32:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, (DataType.PTR, b[1])], outs=[]))
            elif op.operand == Intrinsic.LOAD64:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.PTR, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.STORE64:
                [a, b] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, (DataType.PTR, b[1])], outs=[]))
            elif op.operand == Intrinsic.CAST_PTR:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[(DataType.PTR, op.token.loc)]))
            elif op.operand == Intrinsic.CAST_INT:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.CAST_BOOL:
                [a] = expect_arity(ctx, op, 1)
                type_check_contract(op.token, ctx, Contract(ins=[a], outs=[(DataType.BOOL, op.token.loc)]))
            elif op.operand == Intrinsic.ARGC:
                type_check_contract(op.token, ctx, Contract(ins=[], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.ARGV:
                type_check_contract(op.token, ctx, Contract(ins=[], outs=[(DataType.PTR, op.token.loc)]))
            elif op.operand == Intrinsic.ENVP:
                type_check_contract(op.token, ctx, Contract(ins=[], outs=[(DataType.PTR, op.token.loc)]))
            elif op.operand == Intrinsic.HERE:
                type_check_contract(op.token, ctx, Contract(ins=[], outs=[(DataType.INT, op.token.loc), (DataType.PTR, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL0:
                type_check_contract(op.token, ctx, Contract(ins=[(DataType.INT, op.token.loc)], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL1:
                [a, number] = expect_arity(ctx, op, 2)
                type_check_contract(op.token, ctx, Contract(ins=[a, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL2:
                [a, b, number] = expect_arity(ctx, op, 3)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL3:
                [a, b, c, number] = expect_arity(ctx, op, 4)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, c, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL4:
                [a, b, c, d, number] = expect_arity(ctx, op, 5)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, c, d, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL5:
                [a, b, c, d, e, number] = expect_arity(ctx, op, 6)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, c, d, e, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.SYSCALL6:
                [a, b, c, d, e, f, number] = expect_arity(ctx, op, 7)
                type_check_contract(op.token, ctx, Contract(ins=[a, b, c, d, e, f, (DataType.INT, number[1])], outs=[(DataType.INT, op.token.loc)]))
            elif op.operand == Intrinsic.STOP:
                # TODO: we need some sort of a flag that would allow us to ignore all the stop requests
                compiler_diagnostic(op.token.loc, "DEBUG", "Stopping the compilation. Current stack state:")
                if len(ctx.stack) > 0:
                    for typ, loc in reversed(ctx.stack):
                        compiler_diagnostic(loc, "ITEM", f"type `{DATATYPE_NAMES[typ]}`")
                else:
                    compiler_diagnostic(op.token.loc, "DEBUG", "<EMPTY>")
                exit(1)
            else:
                assert False, "unreachable"
            ctx.ip += 1
        elif op.typ == OpType.IF:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL, op.token.loc)], outs=[]))
            ctx.ip += 1
            assert isinstance(op.operand, OpAddr)
            contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, outs=copy(ctx.outs)))
            ctx = contexts[-1]
        elif op.typ == OpType.IFSTAR:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL, op.token.loc)], outs=[]))
            ctx.ip += 1
            assert isinstance(op.operand, OpAddr)
            contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, outs=copy(ctx.outs)))
            ctx = contexts[-1]
        elif op.typ == OpType.WHILE:
            ctx.ip += 1
        elif op.typ == OpType.END:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.ELSE:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.DO:
            type_check_contract(op.token, ctx, Contract(ins=[(DataType.BOOL, op.token.loc)], outs=[]))
            assert isinstance(op.operand, OpAddr)
            if ctx.ip in visited_dos:
                expected_types = list(map(lambda x: x[0], visited_dos[ctx.ip]))
                actual_types = list(map(lambda x: x[0], ctx.stack))
                if expected_types != actual_types:
                    compiler_error(op.token.loc, 'Loops are not allowed to alter types and amount of elements on the stack between iterations!')
                    compiler_note(op.token.loc, '-- Stack BEFORE a single iteration --')
                    if len(visited_dos[ctx.ip]) == 0:
                        compiler_note(op.token.loc, '<empty>')
                    else:
                        for typ, loc in visited_dos[ctx.ip]:
                            compiler_note(loc, f"type `{DATATYPE_NAMES[typ]}`")
                    compiler_note(op.token.loc, '-- Stack AFTER a single iteration --')
                    if len(ctx.stack) == 0:
                        compiler_note(op.token.loc, '<empty>')
                    else:
                        for typ, loc in ctx.stack:
                            compiler_note(loc, f"type `{DATATYPE_NAMES[typ]}`")
                    exit(1)
                contexts.pop()
            else:
                visited_dos[ctx.ip] = copy(ctx.stack)
                ctx.ip += 1
                contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, outs=copy(ctx.outs)))
                ctx = contexts[-1]
        else:
            assert False, "unreachable"

def generate_nasm_linux_x86_64(program: Program, out_file_path: str):
    strs: List[bytes] = []
    with open(out_file_path, "w") as out:
        out.write("BITS 64\n")
        out.write("segment .text\n")
        out.write("print:\n")
        out.write("    mov     r9, -3689348814741910323\n")
        out.write("    sub     rsp, 40\n")
        out.write("    mov     BYTE [rsp+31], 10\n")
        out.write("    lea     rcx, [rsp+30]\n")
        out.write(".L2:\n")
        out.write("    mov     rax, rdi\n")
        out.write("    lea     r8, [rsp+32]\n")
        out.write("    mul     r9\n")
        out.write("    mov     rax, rdi\n")
        out.write("    sub     r8, rcx\n")
        out.write("    shr     rdx, 3\n")
        out.write("    lea     rsi, [rdx+rdx*4]\n")
        out.write("    add     rsi, rsi\n")
        out.write("    sub     rax, rsi\n")
        out.write("    add     eax, 48\n")
        out.write("    mov     BYTE [rcx], al\n")
        out.write("    mov     rax, rdi\n")
        out.write("    mov     rdi, rdx\n")
        out.write("    mov     rdx, rcx\n")
        out.write("    sub     rcx, 1\n")
        out.write("    cmp     rax, 9\n")
        out.write("    ja      .L2\n")
        out.write("    lea     rax, [rsp+32]\n")
        out.write("    mov     edi, 1\n")
        out.write("    sub     rdx, rax\n")
        out.write("    xor     eax, eax\n")
        out.write("    lea     rsi, [rsp+32+rdx]\n")
        out.write("    mov     rdx, r8\n")
        out.write("    mov     rax, 1\n")
        out.write("    syscall\n")
        out.write("    add     rsp, 40\n")
        out.write("    ret\n")
        out.write("global _start\n")
        out.write("_start:\n")
        out.write("    mov [args_ptr], rsp\n")
        out.write("    mov rax, ret_stack_end\n")
        out.write("    mov [ret_stack_rsp], rax\n")
        for ip in range(len(program.ops)):
            op = program.ops[ip]
            assert len(OpType) == 18, "Exhaustive ops handling in generate_nasm_linux_x86_64"
            out.write("addr_%d:\n" % ip)
            if op.typ in [OpType.PUSH_INT, OpType.PUSH_BOOL, OpType.PUSH_PTR]:
                assert isinstance(op.operand, int), f"This could be a bug in the parsing step {op.operand}"
                out.write("    mov rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8')
                n = len(value)
                out.write("    mov rax, %d\n" % n)
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8') + b'\0'
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_MEM:
                assert isinstance(op.operand, MemAddr), "This could be a bug in the parsing step"
                out.write("    mov rax, mem\n")
                out.write("    add rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_LOCAL_MEM:
                assert isinstance(op.operand, MemAddr)
                out.write("    mov rax, [ret_stack_rsp]\n");
                out.write("    add rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ in [OpType.IF, OpType.IFSTAR]:
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step {op.operand}"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.WHILE:
                pass
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.END:
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.DO:
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.SKIP_PROC:
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step: {op.operand}"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.PREP_PROC:
                assert isinstance(op.operand, int)
                out.write("    sub rsp, %d\n" % op.operand)
                out.write("    mov [ret_stack_rsp], rsp\n")
                out.write("    mov rsp, rax\n")
            elif op.typ == OpType.CALL:
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step: {op.operand}"
                out.write("    mov rax, rsp\n")
                out.write("    mov rsp, [ret_stack_rsp]\n")
                out.write("    call addr_%d\n" % op.operand)
                out.write("    mov [ret_stack_rsp], rsp\n")
                out.write("    mov rsp, rax\n")
            elif op.typ == OpType.RET:
                assert isinstance(op.operand, int)
                out.write("    mov rax, rsp\n")
                out.write("    mov rsp, [ret_stack_rsp]\n")
                out.write("    add rsp, %d\n" % op.operand)
                out.write("    ret\n")
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 45, "Exhaustive intrinsic handling in generate_nasm_linux_x86_64()"
                if op.operand == Intrinsic.PLUS:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    add rax, rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.MINUS:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    sub rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.MUL:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    mul rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.MAX:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    cmp rbx, rax\n")
                    out.write("    cmovge rax, rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.DIVMOD:
                    out.write("    xor rdx, rdx\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    div rbx\n")
                    out.write("    push rax\n");
                    out.write("    push rdx\n");
                elif op.operand == Intrinsic.SHR:
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shr rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.SHL:
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shl rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.OR:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    or rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.AND:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    and rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.NOT:
                    out.write("    pop rax\n")
                    out.write("    not rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.PRINT:
                    out.write("    pop rdi\n")
                    out.write("    call print\n")
                elif op.operand == Intrinsic.EQ:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmove rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GT:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovg rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LT:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovl rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GE:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovge rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LE:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovle rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.NE:
                    out.write("    mov rcx, 0\n")
                    out.write("    mov rdx, 1\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    cmp rax, rbx\n")
                    out.write("    cmovne rcx, rdx\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.DUP:
                    out.write("    pop rax\n")
                    out.write("    push rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SWAP:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.DROP:
                    out.write("    pop rax\n")
                elif op.operand == Intrinsic.OVER:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.ROT:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rcx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LOAD8:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE8:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.LOAD16:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE16:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bx\n");
                elif op.operand == Intrinsic.LOAD32:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov ebx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE32:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], ebx\n");
                elif op.operand == Intrinsic.LOAD64:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE64:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.ARGC:
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    mov rax, [rax]\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.ARGV:
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    add rax, 8\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.ENVP:
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    mov rax, [rax]\n")
                    out.write("    add rax, 2\n")
                    out.write("    shl rax, 3\n")
                    out.write("    mov rbx, [args_ptr]\n")
                    out.write("    add rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode('utf-8')
                    n = len(value)
                    out.write("    mov rax, %d\n" % n)
                    out.write("    push rax\n")
                    out.write("    push str_%d\n" % len(strs))
                    strs.append(value)
                elif op.operand in [Intrinsic.CAST_PTR, Intrinsic.CAST_INT, Intrinsic.CAST_BOOL]:
                    pass
                elif op.operand == Intrinsic.SYSCALL0:
                    out.write("    pop rax\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL1:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL2:
                    out.write("    pop rax\n");
                    out.write("    pop rdi\n");
                    out.write("    pop rsi\n");
                    out.write("    syscall\n");
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL3:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL4:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL5:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    pop r8\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL6:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    pop r8\n")
                    out.write("    pop r9\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.STOP:
                    pass
                else:
                    assert False, "unreachable"
            else:
                assert False, "unreachable"

        out.write("addr_%d:\n" % len(program.ops))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .data\n")
        for index, s in enumerate(strs):
            out.write("str_%d: db %s\n" % (index, ','.join(map(str, list(s)))))
        out.write("segment .bss\n")
        out.write("args_ptr: resq 1\n")
        out.write("ret_stack_rsp: resq 1\n")
        out.write("ret_stack: resb %d\n" % X86_64_RET_STACK_CAP)
        out.write("ret_stack_end:\n")
        out.write("mem: resb %d\n" % program.memory_capacity)

assert len(Keyword) == 16, f"Exhaustive KEYWORD_NAMES definition. {len(Keyword)}"
KEYWORD_BY_NAMES: Dict[str, Keyword] = {
    'if': Keyword.IF,
    'if*': Keyword.IFSTAR,
    'else': Keyword.ELSE,
    'while': Keyword.WHILE,
    'do': Keyword.DO,
    'include': Keyword.INCLUDE,
    'memory': Keyword.MEMORY,
    'proc': Keyword.PROC,
    'end': Keyword.END,
    'const': Keyword.CONST,
    'offset': Keyword.OFFSET,
    'reset': Keyword.RESET,
    'assert': Keyword.ASSERT,
    'in': Keyword.IN,
    '--': Keyword.BIKESHEDDER,
    'inline': Keyword.INLINE,
}
KEYWORD_NAMES: Dict[Keyword, str] = {v: k for k, v in KEYWORD_BY_NAMES.items()}

assert len(Intrinsic) == 45, "Exhaustive INTRINSIC_BY_NAMES definition"
INTRINSIC_BY_NAMES: Dict[str, Intrinsic] = {
    '+': Intrinsic.PLUS,
    '-': Intrinsic.MINUS,
    '*': Intrinsic.MUL,
    'divmod': Intrinsic.DIVMOD,
    'max': Intrinsic.MAX,
    'print': Intrinsic.PRINT,
    '=': Intrinsic.EQ,
    '>': Intrinsic.GT,
    '<': Intrinsic.LT,
    '>=': Intrinsic.GE,
    '<=': Intrinsic.LE,
    '!=': Intrinsic.NE,
    'shr': Intrinsic.SHR,
    'shl': Intrinsic.SHL,
    'or': Intrinsic.OR,
    'and': Intrinsic.AND,
    'not': Intrinsic.NOT,
    'dup': Intrinsic.DUP,
    'swap': Intrinsic.SWAP,
    'drop': Intrinsic.DROP,
    'over': Intrinsic.OVER,
    'rot': Intrinsic.ROT,
    '!8': Intrinsic.STORE8,
    '@8': Intrinsic.LOAD8,
    '!16': Intrinsic.STORE16,
    '@16': Intrinsic.LOAD16,
    '!32': Intrinsic.STORE32,
    '@32': Intrinsic.LOAD32,
    '!64': Intrinsic.STORE64,
    '@64': Intrinsic.LOAD64,
    'cast(ptr)': Intrinsic.CAST_PTR,
    'cast(int)': Intrinsic.CAST_INT,
    'cast(bool)': Intrinsic.CAST_BOOL,
    'argc': Intrinsic.ARGC,
    'argv': Intrinsic.ARGV,
    'envp': Intrinsic.ENVP,
    'here': Intrinsic.HERE,
    'syscall0': Intrinsic.SYSCALL0,
    'syscall1': Intrinsic.SYSCALL1,
    'syscall2': Intrinsic.SYSCALL2,
    'syscall3': Intrinsic.SYSCALL3,
    'syscall4': Intrinsic.SYSCALL4,
    'syscall5': Intrinsic.SYSCALL5,
    'syscall6': Intrinsic.SYSCALL6,
    '???': Intrinsic.STOP,
}
INTRINSIC_NAMES: Dict[Intrinsic, str] = {v: k for k, v in INTRINSIC_BY_NAMES.items()}

class HumanNumber(Enum):
    Singular=auto()
    Plural=auto()

def human(obj: TokenType, number: HumanNumber = HumanNumber.Singular) -> str:
    '''Human readable representation of an object that can be used in error messages'''
    assert len(HumanNumber) == 2, "Exhaustive handling of number category in human()"
    if number == HumanNumber.Singular:
        assert len(TokenType) == 6, "Exhaustive handling of token types in human()"
        if obj == TokenType.WORD:
            return "a word"
        elif obj == TokenType.INT:
            return "an integer"
        elif obj == TokenType.STR:
            return "a string"
        elif obj == TokenType.CSTR:
            return "a C-style string"
        elif obj == TokenType.CHAR:
            return "a character"
        elif obj == TokenType.KEYWORD:
            return "a keyword"
        else:
            assert False, "unreachable"
    elif number == HumanNumber.Plural:
        assert len(TokenType) == 6, "Exhaustive handling of token types in human()"
        if obj == TokenType.WORD:
            return "words"
        elif obj == TokenType.INT:
            return "integers"
        elif obj == TokenType.STR:
            return "strings"
        elif obj == TokenType.CSTR:
            return "C-style strings"
        elif obj == TokenType.CHAR:
            return "characters"
        elif obj == TokenType.KEYWORD:
            return "keywords"
        else:
            assert False, "unreachable"
    else:
        assert False, "unreachable"

@dataclass
class Memory:
    offset: MemAddr
    loc: Loc

@dataclass
class Proc:
    inline: bool
    addr: OpAddr
    loc: Loc
    contract: Contract
    local_memories: Dict[str, Memory]
    local_memory_capacity: int

@dataclass
class Const:
    value: int
    typ: DataType
    loc: Loc

@dataclass
class ParseContext:
    stack: List[OpAddr] = field(default_factory=list)
    ops: List[Op] = field(default_factory=list)
    memories: Dict[str, Memory] = field(default_factory=dict)
    memory_capacity: int = 0
    procs: Dict[str, Proc] = field(default_factory=dict)
    consts: Dict[str, Const] = field(default_factory=dict)
    current_proc: Optional[Proc] = None
    iota: int = 0
    # TODO: consider getting rid of the ip variable in ParseContext
    ip: OpAddr = 0

def check_name_redefinition(ctx: ParseContext, name: str, loc: Loc):
    if ctx.current_proc is None:
        if name in ctx.memories:
            compiler_error(loc, "redefinition of a memory region `%s`" % name)
            compiler_note(ctx.memories[name].loc, "the original definition is located here")
            exit(1)
    else:
        if name in ctx.current_proc.local_memories:
            compiler_error(loc, "redefinition of a local memory region `%s`" % name)
            compiler_note(ctx.current_proc.local_memories[name].loc, "the original definition is located here")
            exit(1)
    if name in INTRINSIC_BY_NAMES:
        compiler_error(loc, "redefinition of an intrinsic word `%s`" % (name, ))
        exit(1)
    if name in ctx.procs:
        compiler_error(loc, "redefinition of a proc `%s`" % (name, ))
        compiler_note(ctx.procs[name].loc, "the original definition is located here")
        exit(1)
    if name in ctx.consts:
        compiler_error(loc, "redefinition of a constant `%s`" % (name, ))
        compiler_note(ctx.consts[name].loc, "the original definition is located here")
        exit(1)

# TODO: use type contracts for eval_const_value ffs
def eval_const_value(ctx: ParseContext, rtokens: List[Token]) -> Tuple[int, DataType]:
    stack: List[Tuple[int, DataType]] = []
    while len(rtokens) > 0:
        token = rtokens.pop()
        if token.typ == TokenType.KEYWORD:
            assert isinstance(token.value, Keyword)
            if token.value == Keyword.END:
                break
            elif token.value == Keyword.OFFSET:
                if len(stack) < 1:
                    compiler_error(token.loc, f"not enough arguments for `{KEYWORD_NAMES[token.value]}` keyword")
                    exit(1)
                offset, typ = stack.pop()
                if typ is not DataType.INT:
                    compiler_error(token.loc, f"`{KEYWORD_NAMES[token.value]}` expects type {DataType.INT} but got {typ}")
                    exit(1)
                stack.append((ctx.iota, DataType.INT))
                ctx.iota += offset
            elif token.value == Keyword.RESET:
                stack.append((ctx.iota, DataType.INT))
                ctx.iota = 0
            else:
                compiler_error(token.loc, f"unsupported keyword `{KEYWORD_NAMES[token.value]}` in compile time evaluation")
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int)
            stack.append((token.value, DataType.INT))
        elif token.typ == TokenType.WORD:
            assert isinstance(token.value, str)
            if token.value == INTRINSIC_NAMES[Intrinsic.PLUS]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a, a_type = stack.pop()
                b, b_type = stack.pop()

                if a_type == DataType.INT and b_type == DataType.INT:
                    stack.append((a + b, DataType.INT))
                elif a_type == DataType.INT and b_type == DataType.PTR:
                    stack.append((a + b, DataType.PTR))
                elif a_type == DataType.PTR and b_type == DataType.INT:
                    stack.append((a + b, DataType.PTR))
                else:
                    compiler_error(token.loc, f"Invalid argument types for `{token.value}` intrinsic: {(a_type, b_type)}")
                    compiler_note(token.loc, f"Expected:")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.INT)}")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.PTR)}")
                    compiler_note(token.loc, f"  {(DataType.PTR, DataType.INT)}")
                    exit(1)
            elif token.value == INTRINSIC_NAMES[Intrinsic.MINUS]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                b, b_type = stack.pop()
                a, a_type = stack.pop()

                if a_type == DataType.INT and b_type == DataType.INT:
                    stack.append((a - b, DataType.INT))
                elif a_type == DataType.PTR and b_type == DataType.PTR:
                    stack.append((a - b, DataType.INT))
                elif a_type == DataType.PTR and b_type == DataType.INT:
                    stack.append((a - b, DataType.PTR))
                else:
                    compiler_error(token.loc, f"Invalid argument types for `{token.value}` intrinsic: {(a_type, b_type)}")
                    compiler_note(token.loc, f"Expected:")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.INT)}")
                    compiler_note(token.loc, f"  {(DataType.PTR, DataType.PTR)}")
                    compiler_note(token.loc, f"  {(DataType.PTR, DataType.INT)}")
                    exit(1)
            elif token.value == INTRINSIC_NAMES[Intrinsic.MUL]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a, a_type = stack.pop()
                b, b_type = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((a * b, DataType.INT))
                else:
                    compiler_error(token.loc, f"Invalid argument types for `{token.value}` intrinsic: {(a_type, b_type)}")
                    compiler_note(token.loc, f"Expected:")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.INT)}")
                    exit(1)
            elif token.value == INTRINSIC_NAMES[Intrinsic.DIVMOD]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a, a_type = stack.pop()
                b, b_type = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((b//a, DataType.INT))
                    stack.append((b%a, DataType.INT))
                else:
                    compiler_error(token.loc, f"Invalid argument types for `{token.value}` intrinsic: {(a_type, b_type)}")
                    compiler_note(token.loc, f"Expected:")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.INT)}")
                    exit(1)
            elif token.value == INTRINSIC_NAMES[Intrinsic.DROP]:
                if len(stack) < 1:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                stack.pop()
            elif token.value == INTRINSIC_NAMES[Intrinsic.CAST_BOOL]:
                if len(stack) < 1:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                value, typ = stack.pop()
                stack.append((value, DataType.BOOL))
            elif token.value == INTRINSIC_NAMES[Intrinsic.CAST_INT]:
                if len(stack) < 1:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                value, typ = stack.pop()
                stack.append((value, DataType.INT))
            elif token.value == INTRINSIC_NAMES[Intrinsic.CAST_PTR]:
                if len(stack) < 1:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                value, typ = stack.pop()
                stack.append((value, DataType.PTR))
            elif token.value == INTRINSIC_NAMES[Intrinsic.EQ]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a, a_type = stack.pop()
                b, b_type = stack.pop()

                if a_type != b_type:
                    compiler_error(token.loc, f"intrinsic `{token.value}` expects the arguments to have the same type. The actual types are")
                    compiler_note(token.loc, f"    {(a_type, b_type)}")
                    exit(1)

                stack.append((int(a == b), DataType.BOOL))
            elif token.value == INTRINSIC_NAMES[Intrinsic.MAX]:
                if len(stack) < 2:
                    compiler_error(token.loc, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a, a_type = stack.pop()
                b, b_type = stack.pop()
                if a_type == b_type and a_type == DataType.INT:
                    stack.append((max(a, b), DataType.INT))
                else:
                    compiler_error(token.loc, f"Invalid argument types for `{token.value}` intrinsic: {(a_type, b_type)}")
                    compiler_note(token.loc, f"Expected:")
                    compiler_note(token.loc, f"  {(DataType.INT, DataType.INT)}")
                    exit(1)
            elif token.value in ctx.consts:
                const = ctx.consts[token.value]
                stack.append((const.value, const.typ))
            else:
                compiler_error(token.loc, f"unsupported word `{token.value}` in compile time evaluation")
                exit(1)
        else:
            compiler_error(token.loc, f"{human(token.typ, HumanNumber.Plural)} are not supported in compile time evaluation")
            exit(1)
    if len(stack) != 1:
        compiler_error(token.loc, "The result of expression in compile time evaluation must be a single number")
        exit(1)
    return stack.pop()

def parse_contract_list(rtokens: List[Token], stoppers: List[Keyword]) -> Tuple[List[Tuple[DataType, Loc]], Keyword]:
    args: List[Tuple[DataType, Loc]] = []
    while len(rtokens) > 0:
        token = rtokens.pop()
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str)
            if token.value in DATATYPE_BY_NAME:
                args.append((DATATYPE_BY_NAME[token.value], token.loc))
            else:
                compiler_error(token.loc, f"Unknown data type {token.value}")
                exit(1)
        elif token.typ == TokenType.KEYWORD:
            assert isinstance(token.value, Keyword)
            if token.value in stoppers:
                return (args, token.value)
            else:
                compiler_error(token.loc, f"Unexpected keyword {KEYWORD_NAMES[token.value]}")
                exit(1)
        else:
            compiler_error(token.loc, f"{human(token.typ, HumanNumber.Plural)} are not allowed in procedure definition.")
            exit(1)

    compiler_error(token.loc, f"Unexpected end of file. Expected keywords: ")
    for keyword in stoppers:
        compiler_note(token.loc, f"  {KEYWORD_NAMES[keyword]}")
    exit(1)

def parse_proc_contract(rtokens: List[Token]) -> Contract:
    contract = Contract(ins=[], outs=[])
    contract.ins, stopper = parse_contract_list(rtokens, [Keyword.BIKESHEDDER, Keyword.IN])
    if stopper == Keyword.IN:
        return contract
    contract.outs, stopper = parse_contract_list(rtokens, [Keyword.IN])
    assert stopper == Keyword.IN
    return contract

def introduce_proc(ctx: ParseContext, token: Token, rtokens: List[Token], inline=False):
    if ctx.current_proc is None:
        ctx.ops.append(Op(typ=OpType.SKIP_PROC, token=token))
        ctx.stack.append(ctx.ip)
        ctx.ip += 1

        proc_addr = ctx.ip
        ctx.ops.append(Op(typ=OpType.PREP_PROC, token=token))
        ctx.stack.append(ctx.ip)
        ctx.ip += 1

        if len(rtokens) == 0:
            compiler_error(token.loc, "expected procedure name but found nothing")
            exit(1)
        token = rtokens.pop()
        if token.typ != TokenType.WORD:
            compiler_error(token.loc, "expected procedure name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
            exit(1)
        assert isinstance(token.value, str), "This is probably a bug in the lexer"
        proc_loc = token.loc
        proc_name = token.value
        check_name_redefinition(ctx, token.value, token.loc)

        proc_contract = parse_proc_contract(rtokens)

        ctx.procs[proc_name] = Proc(
            addr=proc_addr,
            loc=token.loc,
            local_memories={},
            local_memory_capacity=0,
            contract=proc_contract,
            inline=inline
        )
        ctx.current_proc = ctx.procs[proc_name]
    else:
        # TODO: forbid constant definition inside of proc
        compiler_error(token.loc, "defining procedures inside of procedures is not allowed")
        compiler_note(ctx.current_proc.loc, "the current procedure starts here")
        exit(1)

def parse_program_from_tokens(ctx: ParseContext, tokens: List[Token], include_paths: List[str], included: int):
    rtokens: List[Token] = list(reversed(tokens))
    while len(rtokens) > 0:
        token = rtokens.pop()
        assert len(TokenType) == 6, "Exhaustive token handling in parse_program_from_tokens"
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in INTRINSIC_BY_NAMES:
                ctx.ops.append(Op(typ=OpType.INTRINSIC, token=token, operand=INTRINSIC_BY_NAMES[token.value]))
                ctx.ip += 1
            elif ctx.current_proc is not None and token.value in ctx.current_proc.local_memories:
                ctx.ops.append(Op(typ=OpType.PUSH_LOCAL_MEM, token=token, operand=ctx.current_proc.local_memories[token.value].offset))
                ctx.ip += 1
            elif token.value in ctx.memories:
                ctx.ops.append(Op(typ=OpType.PUSH_MEM, token=token, operand=ctx.memories[token.value].offset))
                ctx.ip += 1
            elif token.value in ctx.procs:
                proc = ctx.procs[token.value]
                if proc.inline:
                    proc_ip = proc.addr
                    assert ctx.ops[proc_ip].typ == OpType.PREP_PROC
                    proc_ip += 1
                    while ctx.ops[proc_ip].typ != OpType.RET:
                        ctx.ops.append(ctx.ops[proc_ip])
                        ctx.ip += 1
                        proc_ip += 1
                else:
                    ctx.ops.append(Op(typ=OpType.CALL, token=token, operand=proc.addr))
                    ctx.ip += 1
            elif token.value in ctx.consts:
                const = ctx.consts[token.value]
                if const.typ == DataType.INT:
                    ctx.ops.append(Op(typ=OpType.PUSH_INT, token=token, operand=const.value))
                elif const.typ == DataType.BOOL:
                    ctx.ops.append(Op(typ=OpType.PUSH_BOOL, token=token, operand=const.value))
                elif const.typ == DataType.PTR:
                    ctx.ops.append(Op(typ=OpType.PUSH_PTR, token=token, operand=const.value))
                else:
                    assert False, "unreachable"
                ctx.ip += 1
            else:
                compiler_error(token.loc, "unknown word `%s`" % token.value)
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            ctx.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ctx.ip += 1
        elif token.typ == TokenType.STR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            ctx.ops.append(Op(typ=OpType.PUSH_STR, operand=token.value, token=token));
            ctx.ip += 1
        elif token.typ == TokenType.CSTR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            ctx.ops.append(Op(typ=OpType.PUSH_CSTR, operand=token.value, token=token));
            ctx.ip += 1
        elif token.typ == TokenType.CHAR:
            assert isinstance(token.value, int)
            ctx.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token));
            ctx.ip += 1
        elif token.typ == TokenType.KEYWORD:
            assert len(Keyword) == 16, "Exhaustive keywords handling in parse_program_from_tokens()"
            if token.value == Keyword.IF:
                if ctx.current_proc is not None and ctx.current_proc.inline:
                    compiler_error(ctx.current_proc.loc, "no conditions in inline procedures");
                    compiler_note(token.loc, "condition is used here")
                    exit(1)

                ctx.ops.append(Op(typ=OpType.IF, token=token))
                ctx.stack.append(ctx.ip)
                ctx.ip += 1
            elif token.value == Keyword.IFSTAR:
                if len(ctx.stack) == 0:
                    compiler_error(token.loc, '`if*` can only come after `else`')
                    exit(1)

                else_ip = ctx.stack[-1]
                if ctx.ops[else_ip].typ != OpType.ELSE:
                    compiler_error(ctx.ops[else_ip].token.loc, '`if*` can only come after `else`')
                    exit(1)
                ctx.ops.append(Op(typ=OpType.IFSTAR, token=token))
                ctx.stack.append(ctx.ip)
                ctx.ip += 1
            elif token.value == Keyword.ELSE:
                if len(ctx.stack) == 0:
                    compiler_error(token.loc, '`else` can only come after `if` or `if*`')
                    exit(1)

                if_ip = ctx.stack.pop()
                if ctx.ops[if_ip].typ == OpType.IF:
                    ctx.ops[if_ip].operand = ctx.ip + 1
                    ctx.stack.append(ctx.ip)
                    ctx.ops.append(Op(typ=OpType.ELSE, token=token))
                    ctx.ip += 1
                elif ctx.ops[if_ip].typ == OpType.IFSTAR:
                    else_before_ifstar_ip = None if len(ctx.stack) == 0 else ctx.stack.pop()
                    assert else_before_ifstar_ip is not None and ctx.ops[else_before_ifstar_ip].typ == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."

                    ctx.ops[if_ip].operand = ctx.ip + 1
                    ctx.ops[else_before_ifstar_ip].operand = ctx.ip

                    ctx.stack.append(ctx.ip)
                    ctx.ops.append(Op(typ=OpType.ELSE, token=token))
                    ctx.ip += 1
                else:
                    compiler_error(ctx.ops[if_ip].token.loc, f'`else` can only come after `if` or `if*`')
                    exit(1)
            elif token.value == Keyword.END:
                block_ip = ctx.stack.pop()

                if ctx.ops[block_ip].typ == OpType.ELSE:
                    ctx.ops.append(Op(typ=OpType.END, token=token))
                    ctx.ops[block_ip].operand = ctx.ip
                    ctx.ops[ctx.ip].operand = ctx.ip + 1
                elif ctx.ops[block_ip].typ == OpType.DO:
                    ctx.ops.append(Op(typ=OpType.END, token=token))
                    assert ctx.ops[block_ip].operand is not None
                    while_ip = ctx.ops[block_ip].operand
                    assert isinstance(while_ip, OpAddr)

                    if ctx.ops[while_ip].typ != OpType.WHILE:
                        compiler_error(ctx.ops[while_ip].token.loc, '`end` can only close `do` blocks that are preceded by `while`')
                        exit(1)

                    ctx.ops[ctx.ip].operand = while_ip
                    ctx.ops[block_ip].operand = ctx.ip + 1
                elif ctx.ops[block_ip].typ == OpType.PREP_PROC:
                    assert ctx.current_proc is not None
                    ctx.ops[block_ip].operand = ctx.current_proc.local_memory_capacity
                    block_ip = ctx.stack.pop()
                    assert ctx.ops[block_ip].typ == OpType.SKIP_PROC
                    ctx.ops.append(Op(typ=OpType.RET, token=token, operand=ctx.current_proc.local_memory_capacity))
                    ctx.ops[block_ip].operand = ctx.ip + 1
                    ctx.current_proc = None
                elif ctx.ops[block_ip].typ == OpType.IFSTAR:
                    else_before_ifstar_ip = None if len(ctx.stack) == 0 else ctx.stack.pop()
                    assert else_before_ifstar_ip is not None and ctx.ops[else_before_ifstar_ip].typ == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."

                    ctx.ops.append(Op(typ=OpType.END, token=token))
                    ctx.ops[block_ip].operand = ctx.ip
                    ctx.ops[else_before_ifstar_ip].operand = ctx.ip
                    ctx.ops[ctx.ip].operand = ctx.ip + 1
                elif ctx.ops[block_ip].typ == OpType.IF:
                    ctx.ops.append(Op(typ=OpType.END, token=token))
                    ctx.ops[block_ip].operand = ctx.ip
                    ctx.ops[ctx.ip].operand = ctx.ip + 1
                else:
                    compiler_error(ctx.ops[block_ip].token.loc, '`end` can only close `if`, `else`, `do`, or `proc` blocks for now')
                    exit(1)
                ctx.ip += 1
            elif token.value == Keyword.WHILE:
                ctx.ops.append(Op(typ=OpType.WHILE, token=token))
                ctx.stack.append(ctx.ip)
                ctx.ip += 1
            elif token.value == Keyword.DO:
                if ctx.current_proc is not None and ctx.current_proc.inline:
                    compiler_error(ctx.current_proc.loc, "no loops in inline procedures")
                    compiler_note(token.loc, "loop is used here")
                    exit(1)
                ctx.ops.append(Op(typ=OpType.DO, token=token))
                if len(ctx.stack) == 0:
                    compiler_error(token.loc, "`do` is not preceded by `while`")
                    exit(1)
                while_ip = ctx.stack.pop()
                if ctx.ops[while_ip].typ != OpType.WHILE:
                    compiler_error(token.loc, "`do` is not preceded by `while`")
                    exit(1)
                ctx.ops[ctx.ip].operand = while_ip
                ctx.stack.append(ctx.ip)
                ctx.ip += 1
            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "expected path to the include file but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    compiler_error(token.loc, "expected path to the include file to be %s but found %s" % (human(TokenType.STR), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                if included >= INCLUDE_LIMIT:
                    compiler_error(token.loc, f"Include limit is exceeded. A file was included {included} times.")
                    exit(1)
                file_included = False
                try:
                    parse_program_from_file(ctx, token.value, include_paths, included + 1)
                    file_included = True
                except FileNotFoundError:
                    for include_path in include_paths:
                        try:
                            parse_program_from_file(ctx, path.join(include_path, token.value), include_paths, included + 1)
                            file_included = True
                            break
                        except FileNotFoundError:
                            continue
                if not file_included:
                    compiler_error(token.loc, "file `%s` not found" % token.value)
                    exit(1)
            elif token.value == Keyword.ASSERT:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "expected assert messsage but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    compiler_error(token.loc, "expected assert message to be %s but found %s" % (human(TokenType.STR), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                assert_message = token.value
                assert_value, assert_typ = eval_const_value(ctx, rtokens)
                if assert_typ != DataType.BOOL:
                    compiler_error(token.loc, "assertion expects the expression to be of type `bool`")
                    exit(1)
                if assert_value == 0:
                    compiler_error(token.loc, f"Static Assertion Failed: {assert_message}");
                    exit(1)
            elif token.value == Keyword.CONST:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "expected const name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error(token.loc, "expected const name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                const_name = token.value
                const_loc = token.loc
                check_name_redefinition(ctx, token.value, token.loc)
                const_value, const_typ = eval_const_value(ctx, rtokens)
                ctx.consts[const_name] = Const(value=const_value, loc=const_loc, typ=const_typ)
            elif token.value == Keyword.MEMORY:
                if ctx.current_proc is not None and ctx.current_proc.inline:
                    compiler_error(ctx.current_proc.loc, "no local memory in inline procedures!");
                    compiler_note(token.loc, "local memory is defined here")
                    exit(1)

                if len(rtokens) == 0:
                    compiler_error(token.loc, "expected memory name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error(token.loc, "expected memory name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                memory_name = token.value
                memory_loc = token.loc
                memory_size, memory_size_type = eval_const_value(ctx, rtokens)
                if memory_size_type != DataType.INT:
                    compiler_error(token.loc, f"Memory size must be of type {DataType.INT} but it is of type {memory_size_type}")
                    exit(1)
                check_name_redefinition(ctx, token.value, token.loc)
                if ctx.current_proc is None:
                    ctx.memories[memory_name] = Memory(offset=ctx.memory_capacity, loc=memory_loc)
                    ctx.memory_capacity += memory_size
                else:
                    # TODO: local memory regions can shadow the global ones
                    # Is that something we actually want?
                    ctx.current_proc.local_memories[memory_name] = Memory(offset=ctx.current_proc.local_memory_capacity, loc=memory_loc)
                    ctx.current_proc.local_memory_capacity += memory_size
            elif token.value == Keyword.PROC:
                introduce_proc(ctx, token, rtokens)
            elif token.value == Keyword.INLINE:
                if len(rtokens) == 0:
                    compiler_error(token.loc, "Expected `proc` keyword after `inline` but got nothing")
                    exit(1)
                token = rtokens.pop()
                if token.value != Keyword.PROC:
                    compiler_error(token.loc, f"Expected keyword `proc` after `inline` but got `{token.text}`")
                    exit(1)
                introduce_proc(ctx, token, rtokens, inline=True)
            elif token.value in [Keyword.OFFSET, Keyword.RESET]:
                compiler_error(token.loc, f"keyword `{token.text}` is supported only in compile time evaluation context")
                exit(1)
            elif token.value in [Keyword.IN, Keyword.BIKESHEDDER]:
                compiler_error(token.loc, f"Unexpected keyword `{token.text}`")
                exit(1)
            else:
                assert False, 'unreachable';
        else:
            assert False, 'unreachable'

    if len(ctx.stack) > 0:
        compiler_error(ctx.ops[ctx.stack.pop()].token.loc, 'unclosed block')
        exit(1)

def find_col(line: str, start: int, predicate: Callable[[str], bool]) -> int:
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

def unescape_string(s: str) -> str:
    # NOTE: unicode_escape assumes latin-1 encoding, so we kinda have
    # to do this weird round trip
    return s.encode('utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')

def find_string_literal_end(line: str, start: int, quote: str = '"') -> int:
    while start < len(line):
        if line[start] == '\\':
            start += 2
        elif line[start] == quote:
            break
        else:
            start += 1
    return start

def lex_lines(file_path: str, lines: List[str]) -> Generator[Token, None, None]:
    assert len(TokenType) == 6, 'Exhaustive handling of token types in lex_lines'
    row = 0
    str_literal_buf = ""
    while row < len(lines):
        line = lines[row]
        col = find_col(line, 0, lambda x: not x.isspace())
        col_end = 0
        while col < len(line):
            loc = (file_path, row + 1, col + 1)
            if line[col] == '"':
                while row < len(lines):
                    start = col
                    if str_literal_buf == "":
                        start += 1
                    else:
                        line = lines[row]
                    col_end = find_string_literal_end(line, start)
                    if col_end >= len(line) or line[col_end] != '"':
                        str_literal_buf += line[start:]
                        row +=1
                        col = 0
                    else:
                        str_literal_buf += line[start:col_end]
                        break
                if row >= len(lines):
                    compiler_error(loc, "unclosed string literal")
                    exit(1)
                assert line[col_end] == '"'
                col_end += 1
                text_of_token = str_literal_buf
                str_literal_buf = ""
                if col_end < len(line) and line[col_end] == 'c':
                    col_end += 1
                    yield Token(TokenType.CSTR, text_of_token, loc, unescape_string(text_of_token))
                else:
                    yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end, lambda x: not x.isspace())
            elif line[col] == "'":
                col_end = find_string_literal_end(line, col+1, quote="'")
                if col_end >= len(line) or line[col_end] != "'":
                    compiler_error(loc, "unclosed character literal")
                    exit(1)
                text_of_token = line[col+1:col_end]
                char_bytes = unescape_string(text_of_token).encode('utf-8')
                if len(char_bytes) != 1:
                    compiler_error(loc, "only a single byte is allowed inside of a character literal")
                    exit(1)
                yield Token(TokenType.CHAR, text_of_token, loc, char_bytes[0])
                col = find_col(line, col_end+1, lambda x: not x.isspace())
            else:
                col_end = find_col(line, col, lambda x: x.isspace())
                text_of_token = line[col:col_end]

                try:
                    yield Token(TokenType.INT, text_of_token, loc, int(text_of_token))
                except ValueError:
                    if text_of_token in KEYWORD_BY_NAMES:
                        yield Token(TokenType.KEYWORD, text_of_token, loc, KEYWORD_BY_NAMES[text_of_token])
                    else:
                        # TODO: `69//` is recognized as a single word
                        # And not a number plus a comment
                        if text_of_token.startswith("//"):
                            break
                        yield Token(TokenType.WORD, text_of_token, loc, text_of_token)
                col = find_col(line, col_end, lambda x: not x.isspace())
        row += 1

def lex_file(file_path: str) -> List[Token]:
    with open(file_path, "r", encoding='utf-8') as f:
        return [token for token in lex_lines(file_path, f.readlines())]

def parse_program_from_file(ctx: ParseContext, file_path: str, include_paths: List[str], included: int = 0):
    parse_program_from_tokens(ctx, lex_file(file_path), include_paths, included)

def cmd_call_echoed(cmd: List[str], silent: bool) -> int:
    if not silent:
        print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.call(cmd)

# TODO: with a lot of procs the control flow graphs becomes useless even on small programs
# Maybe we should eliminate unreachable code or something
# TODO: test.py never touches generate_control_flow_graph_as_dot_file
# Which leads to constantly forgetting to update the implementation
def generate_control_flow_graph_as_dot_file(program: Program, dot_path: str):
    with open(dot_path, "w") as f:
        f.write("digraph Program {\n")
        assert len(OpType) == 16, f"Exhaustive handling of OpType in generate_control_flow_graph_as_dot_file(), {len(OpType)}"
        for ip in range(len(program.ops)):
            op = program.ops[ip]
            if op.typ == OpType.INTRINSIC:
                assert isinstance(op.operand, Intrinsic)
                f.write(f"    Node_{ip} [label={repr(repr(INTRINSIC_NAMES[op.operand]))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label={op.operand}]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_MEM:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label=\"mem({op.operand})\"]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_LOCAL_MEM:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label=\"local_mem({op.operand})\"]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ in [OpType.IF, OpType.IFSTAR]:
                assert isinstance(op.operand, OpAddr), f"{op.operand}"
                f.write(f"    Node_{ip} [shape=record label=if];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.WHILE:
                f.write(f"    Node_{ip} [shape=record label=while];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.DO:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=do];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=else];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=end];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.SKIP_PROC:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=skip_proc];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.PREP_PROC:
                f.write(f"    Node_{ip} [shape=record label=prep_proc];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.RET:
                f.write(f"    Node_{ip} [shape=record label=ret];\n")
            elif op.typ == OpType.CALL:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=call];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            else:
                assert False, f"unimplemented operation {op.typ}"
        f.write(f"    Node_{len(program.ops)} [label=halt];\n")
        f.write("}\n")

def usage(compiler_name: str):
    print("Usage: %s [OPTIONS] <SUBCOMMAND> [ARGS]" % compiler_name)
    print("  OPTIONS:")
    print("    -debug                Enable debug mode.")
    print("    -I <path>             Add the path to the include search list")
    print("    -unsafe               Disable type checking.")
    print("  SUBCOMMAND:")
    print("    com [OPTIONS] <file>  Compile the program")
    print("      OPTIONS:")
    print("        -r                  Run the program after successful compilation")
    print("        -o <file|dir>       Customize the output path")
    print("        -s                  Silent mode. Don't print any info about compilation phases.")
    print("        -cf                 Dump Control Flow graph of the program in a dot format.")
    print("    check <file>          Just compile to IR and type-check without generating asm or executing.")
    print("    help                  Print this help to stdout and exit with 0 code")

if __name__ == '__main__' and '__file__' in globals():
    argv = sys.argv
    assert len(argv) >= 1
    compiler_name, *argv = argv

    include_paths = ['.', './std/']
    unsafe = False

    while len(argv) > 0:
        if argv[0] == '-debug':
            argv = argv[1:]
            debug = True
        elif argv[0] == '-I':
            argv = argv[1:]
            if len(argv) == 0:
                usage(compiler_name)
                print("[ERROR] no path is provided for `-I` flag", file=sys.stderr)
                exit(1)
            include_path, *argv = argv
            include_paths.append(include_path)
        elif argv[0] == '-unsafe':
            argv = argv[1:]
            unsafe = True
        else:
            break

    if len(argv) < 1:
        usage(compiler_name)
        print("[ERROR] no subcommand is provided", file=sys.stderr)
        exit(1)
    subcommand, *argv = argv

    program_path: Optional[str] = None
    program: Program = Program()

    if subcommand == "check":
        if len(argv) < 1:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the checking", file=sys.stderr)
            exit(1)
        program_path, *argv = argv
        include_paths.append(path.dirname(program_path))
        parse_context = ParseContext()
        parse_program_from_file(parse_context, program_path, include_paths);
        program = Program(ops=parse_context.ops, memory_capacity=parse_context.memory_capacity)
        proc_contracts = {proc.addr: proc.contract for proc in parse_context.procs.values()}
        if not unsafe:
            type_check_program(program, proc_contracts)
    elif subcommand == "com":
        silent = False
        control_flow = False
        run = False
        output_path = None
        while len(argv) > 0:
            arg, *argv = argv
            if arg == '-r':
                run = True
            elif arg == '-s':
                silent = True
            elif arg == '-o':
                if len(argv) == 0:
                    usage(compiler_name)
                    print("[ERROR] no argument is provided for parameter -o", file=sys.stderr)
                    exit(1)
                output_path, *argv = argv
            elif arg == '-cf':
                control_flow = True
            else:
                program_path = arg
                break

        if program_path is None:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the compilation", file=sys.stderr)
            exit(1)

        basename = None
        basedir = None
        if output_path is not None:
            if path.isdir(output_path):
                basename = path.basename(program_path)
                if basename.endswith(PORTH_EXT):
                    basename = basename[:-len(PORTH_EXT)]
                basedir = path.dirname(output_path)
            else:
                basename = path.basename(output_path)
                basedir = path.dirname(output_path)
        else:
            basename = path.basename(program_path)
            if basename.endswith(PORTH_EXT):
                basename = basename[:-len(PORTH_EXT)]
            basedir = path.dirname(program_path)

        # if basedir is empty we should "fix" the path appending the current working directory.
        # So we avoid `com -r` to run command from $PATH.
        if basedir == "":
            basedir = os.getcwd()
        basepath = path.join(basedir, basename)

        include_paths.append(path.dirname(program_path))

        parse_context = ParseContext()
        parse_program_from_file(parse_context, program_path, include_paths);
        program = Program(ops=parse_context.ops, memory_capacity=parse_context.memory_capacity)
        proc_contracts = {proc.addr: proc.contract for proc in parse_context.procs.values()}
        if control_flow:
            dot_path = basepath + ".dot"
            if not silent:
                print(f"[INFO] Generating {dot_path}")
            generate_control_flow_graph_as_dot_file(program, dot_path)
            cmd_call_echoed(["dot", "-Tsvg", "-O", dot_path], silent)
        if not unsafe:
            type_check_program(program, proc_contracts)
        if not silent:
            print("[INFO] Generating %s" % (basepath + ".asm"))
        generate_nasm_linux_x86_64(program, basepath + ".asm")
        cmd_call_echoed(["nasm", "-felf64", basepath + ".asm"], silent)
        cmd_call_echoed(["ld", "-o", basepath, basepath + ".o"], silent)
        if run:
            exit(cmd_call_echoed([basepath] + argv, silent))
    elif subcommand == "help":
        usage(compiler_name)
        exit(0)
    else:
        usage(compiler_name)
        print("[ERROR] unknown subcommand %s" % (subcommand), file=sys.stderr)
        exit(1)
