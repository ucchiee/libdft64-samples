/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

#include <iostream>

#include "branch_pred.h"
#include "ins_helper.h"
#include "libdft_api.h"
#include "pin.H"
#include "tagmap.h"
using std::cerr;
using std::endl;
using std::string;

KNOB<string> KnobTaintSourceFunc(KNOB_MODE_WRITEONCE, "pintool", "func", "main",
                                 "specify function name whose args to taint");

KNOB<UINT32> KnobTaintArgsIndex(KNOB_MODE_APPEND, "pintool", "arg_index", "1",
                                "specify index of arg to taint");
KNOB<UINT32> KnobTaintArgsSize(KNOB_MODE_APPEND, "pintool", "arg_size", "4",
                               "specify size of each args to taint");

static void print_reg(THREADID tid) {
    tag_t color;
    for (unsigned int reg = REG_GR_BASE; reg <= REG_GR_LAST; reg++) {
        cerr << REG_StringShort((REG)reg) << " : ";
        for (unsigned int i = 0; i < TAGS_PER_GPR; i++) {
            color = tagmap_getb_reg(tid, reg, i);
            cerr << color << ", ";
        }
        cerr << endl;
    }
    cerr << endl;
}

static unsigned int arg_index2dft_reg(UINT32 index) {
    switch (index) {
        case 0:
            return DFT_REG_RDI;
        case 1:
            return DFT_REG_RSI;
        case 2:
            return DFT_REG_RDX;
        case 3:
            return DFT_REG_RCX;
        case 4:
            return DFT_REG_R8;
        case 5:
            return DFT_REG_R9;
        default:
            cerr << "7~th args is not supported yet." << endl;
            return 0;
    }
}

static void taint_args(THREADID tid, REG arg_reg) {
    cerr << "===taint_args===" << endl;
    tag_t t = tag_alloc<tag_t>(0);
    cerr << "allocated tag" << endl;
    print_reg(tid);
    for (unsigned int i = 0; i < TAGS_PER_GPR; i++) {
        tagmap_setb_reg(tid, REG_INDX(arg_reg), i, t);
    }
    cerr << "tainted " << REG_StringShort(arg_reg) << " register" << endl;
    print_reg(tid);
}

static void add_taint_source(IMG img, void *v) {
    cerr << "=============add_taint_source=============" << endl;
    if (!IMG_Valid(img)) {
        cerr << "img is invalid, will return" << endl;
        return;
    }
    if (!IMG_IsMainExecutable(img)) {
        cerr << "img is not the main executable, will return" << endl;
        return;
    }

    RTN func_rtn = RTN_FindByName(img, KnobTaintSourceFunc.Value().c_str());
    if (!RTN_Valid(func_rtn)) {
        cerr << "rtn is invalid, will return" << endl;
        return;
    }
    RTN_Open(func_rtn);
    for (UINT32 i = 0; i < KnobTaintArgsIndex.NumberOfValues(); i++) {
        RTN_InsertCall(func_rtn, IPOINT_BEFORE, (AFUNPTR)taint_args,
                       IARG_THREAD_ID, IARG_UINT32,
                       arg_index2dft_reg(KnobTaintArgsIndex.Value(i)),
                       IARG_END);
    }
    cerr << "inserted taint_args to " << KnobTaintSourceFunc.Value() << " rtn"
         << endl;
    RTN_Close(func_rtn);
}

static void check_taint(THREADID tid, REG base_reg, REG index_reg) {
    cerr << "===check_taint===" << endl;
    tag_t color, sum;
    sum = 0;
    print_reg(tid);
    cerr << "checking " << REG_StringShort(base_reg) << " register (base)"
         << endl;
    cerr << "tag : ";
    for (unsigned int i = 0; i < TAGS_PER_GPR; i++) {
        color = tagmap_getb_reg(tid, REG_INDX(base_reg), i);
        cerr << color << ", ";
        sum += color;
    }
    cerr << endl;
    cerr << "checking " << REG_StringShort(index_reg) << " register (index)"
         << endl;
    cerr << "tag : ";
    for (unsigned int i = 0; i < TAGS_PER_GPR; i++) {
        color = tagmap_getb_reg(tid, REG_INDX(index_reg), i);
        cerr << color << ", ";
        sum += color;
    }
    cerr << endl;
    if (sum > 0) {
        cerr << "operand of mov is tainted !!!" << endl;
    }
}

static void instrument_mov(INS ins, void *v) {
    IMG img = IMG_FindByAddress(INS_Address(ins));
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;

    if (INS_OperandCount(ins) != 2) return;
    /* if (!INS_IsMemoryRead(ins)) return; */
    /* if (!INS_IsMov(ins)) return; */
    if (!INS_OperandIsMemory(ins, 1)) return;  // in Intel syntax

    cerr << "===instrument_mov" << endl;
    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
    if (index_reg == REG_INVALID()) {
        cerr << "there is not an index register" << endl;
        return;
    }
    cerr << "index register : " << REG_StringShort(index_reg) << endl;
    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    if (base_reg == REG_INVALID()) {
        cerr << "there is not an base register" << endl;
        return;
    }
    cerr << "base register : " << REG_StringShort(base_reg) << endl;
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)check_taint,
                             IARG_THREAD_ID, IARG_UINT32, base_reg, IARG_UINT32,
                             index_reg, IARG_END);
}

int main(int argc, char **argv) {
    /* initialize symbol processing */
    PIN_InitSymbols();

    /* initialize PIN */
    if (PIN_Init(argc, argv)) {
        cerr << "Sth error in PIN_Init. Plz use the right command line options."
             << std::endl;
        return -1;
    }

    /* validate pintool arguments */
    string funcname = KnobTaintSourceFunc.Value();
    if (funcname.empty()) {
        cerr << "Must specify funcname whose args is taint source" << endl;
        return -1;
    }
    UINT32 num_index = (UINT32)KnobTaintArgsIndex.NumberOfValues();
    UINT32 num_size = (UINT32)KnobTaintArgsSize.NumberOfValues();
    if (num_index == 0 || num_size == 0 || num_index != num_size) {
        cerr << "invalid arg_index or arg_size" << endl;
        cerr << "num_index : " << num_index << endl;
        cerr << "num_size : " << num_size << endl;
        return -1;
    }

    /* initialize libdft64 */
    if (unlikely(libdft_init() != 0)) {
        cerr << "failed to init libdft" << endl;
        libdft_die();
        return -1;
    }

    /* register instrumentation callback */
    IMG_AddInstrumentFunction(add_taint_source, 0);
    INS_AddInstrumentFunction(instrument_mov, 0);

    PIN_StartProgram();

    return 0;
}
