#include "llvm/IR/Function.h"
#include "llvm/Pass.h"

#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <cxxabi.h>
#include <exception>
#include <sstream>
#include <sys/time.h>

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <list>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// #define DANG_DEBUG
#ifdef DANG_DEBUG
#define DEBUG_MSG(err) err
#else
#define DEBUG_MSG(err)
#endif

using namespace llvm;

static std::string demangleName(std::string input) {
    int status;
    char *real_name;

    real_name = abi::__cxa_demangle(input.c_str(), 0, 0, &status);
    if (real_name) {
        std::string res(real_name);
        free(real_name);
        return "c++:" + res;
    } else {
        return input;
    }
}

static AllocaInst *getStackPtr(Value *V) {
    if (isa<AllocaInst>(V)) {
        // DEBUG_MSG(errs() << "Stack variable \n");
        return dyn_cast<AllocaInst>(V);
    }

    if (BitCastInst *BC = dyn_cast<BitCastInst>(V)) {
        return getStackPtr(BC->getOperand(0));
    } else if (PtrToIntInst *PI = dyn_cast<PtrToIntInst>(V)) {
        return getStackPtr(PI->getOperand(0));
    } else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
        return getStackPtr(GEP->getPointerOperand());
    }

    // DEBUG_MSG(errs() << "Not a Stack variable \n");
    return nullptr;
}

static Instruction *nextInst(Instruction *I) {
    BasicBlock::iterator it(I);
    return &*++it;
}

/*
 * The class that has functionality of Liveness Analysis
 */
struct LivenessAnalysis {

    /* Set of live variables at the start of instruction */
    std::unordered_map<Instruction *, std::set<AllocaInst *>> in;
    /* Set of live variables at the end of instruction */
    std::unordered_map<Instruction *, std::set<AllocaInst *>> out;
    /* */
    std::unordered_set<StoreInst *> stores;
    std::unordered_set<LoadInst *> loads;

    Module *M;
    Function *Func;

    LivenessAnalysis(){};

    bool getStoreInstructionLiveness(
        Function &F, std::map<AllocaInst *, std::set<CallInst *>> calls, std::set<AllocaInst *> vars,
        std::unordered_map<AllocaInst *, std::vector<StoreInst *>>
            &stores_to_instr, std::unordered_map<AllocaInst *, std::vector<LoadInst *>>
            &loads_to_instr) {
        stores.clear();
        loads.clear();

        for (AllocaInst *AI : vars) {
            /* Backward sink to see which store instruction can call instructions reach */
            {            
                /* If a instruction can reach a target CallInst in calls */
                std::unordered_map<Instruction *, bool> in;
                std::unordered_map<Instruction *, bool> out;
                /* Init result */
                for (Instruction *ci : calls[AI]) {
                    in[ci] = true;
                }

                // DEBUG_MSG(errs() << "stores_to_instr " << *AI << "\n");
                // for (auto i : stores_to_instr[AI]) {
                //     DEBUG_MSG(errs() << "ins: " << *i << "\n");
                // }
                // DEBUG_MSG(errs() << "loads_to_instr " << *AI << "\n");
                // for (auto i : loads_to_instr[AI]) {
                //     DEBUG_MSG(errs() << "ins: " << *i << "\n");
                // }
                // for (auto si : stores_to_instr[AI]) {
                //     in[si] = false;
                // }
                bool changed = true;

                while (changed) {
                    changed = false;
                    for (BasicBlock &BB : F) {
                        for (auto it = BB.rbegin(), e = BB.rend(); it != e; it++) {
                            Instruction *I = &*it;
                            bool in_res = out[I] | in[I];

                            if (in_res != in[I]) {
                                if (std::find(stores_to_instr[AI].begin(),
                                              stores_to_instr[AI].end(), I)
                                            == stores_to_instr[AI].end()) {
                                    in[I] = in_res;
                                    changed = true;

                                }
                            }

                            bool out_res;

                            if (I == BB.getTerminator()) {

                                out_res = out[I];

                                if (out_res) {
                                    continue;
                                }
                                if (isa<BranchInst>(I)) {
                                    BranchInst *BI = dyn_cast<BranchInst>(I);
                                    for (unsigned int i = 0;
                                        i < BI->getNumSuccessors(); i++) {
                                        BasicBlock *n = BI->getSuccessor(i);
                                        Instruction *ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<StoreInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (in[ni]) {
                                            out_res = true;
                                        }
                                    }
                                } else if (isa<SwitchInst>(I)) {
                                    SwitchInst *SI = dyn_cast<SwitchInst>(I);
                                    for (unsigned int i = 0;
                                        i < SI->getNumSuccessors(); i++) {
                                        BasicBlock *n = SI->getSuccessor(i);
                                        Instruction *ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<StoreInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (in[ni]) {
                                            out_res = true;
                                        }
                                    }
                                } else if (isa<IndirectBrInst>(I)) {
                                    IndirectBrInst *IBI =
                                        dyn_cast<IndirectBrInst>(I);
                                    for (unsigned int i = 0;
                                        i < IBI->getNumSuccessors(); i++) {
                                        BasicBlock *n = IBI->getSuccessor(i);
                                        Instruction *ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<StoreInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (in[ni]) {
                                            out_res = true;
                                        }
                                    }
                                } else if (isa<ReturnInst>(I)) {

                                } else if (isa<UnreachableInst>(I)) {

                                } else {
                                    DEBUG_MSG(errs() << "Unknown: " << *I << "\n");
                                }

                            } else if (isa<StoreInst>(I) || isa<CallInst>(I)) {

                                Instruction *ni = I;
                                do {
                                    ni = nextInst(ni);
                                } while (
                                    ni != BB.getTerminator() &&
                                    !(isa<StoreInst>(ni) || isa<CallInst>(ni)));
                                assert(ni);

                                // DEBUG_MSG(errs() << "Current: " << *I << " Next: " << *ni << " Live: " << (in[ni]? "true":"false" )<< "\n");
                                out_res = in[ni];

                            } else {
                                continue;
                            }

                            /* Update if anything changes */
                            if (out_res != out[I]) {
                                // DEBUG_MSG(errs() << *I << " =x= " << *AI << "\n");
                                out[I] = out_res;
                                // DEBUG_MSG(errs() << "stores_to_instr " << *AI << "\n");
                                // for (auto i : stores_to_instr[AI]) {
                                //     DEBUG_MSG(errs() << "ins: " << *i << "\n");
                                // }
                                if (std::find(stores_to_instr[AI].begin(),
                                            stores_to_instr[AI].end(),
                                            I) != stores_to_instr[AI].end()) {
                                    stores.insert(cast<StoreInst>(I));
                                }
                                changed = true;
                            }

                            // if (isa<StoreInst>(I)) {
                            //     StoreInst *SI = dyn_cast<StoreInst>(I);

                            //     // if (SI->getValueOperand()
                            //     //         ->getType()
                            //     //         ->isPointerTy()) {
                            //     AllocaInst *ai =
                            //         getStackPtr(SI->getPointerOperand());
                            //     if (AI == ai) {
                            //         in_res = false;
                            //         if (out[I]) {
                            //             stores.insert(SI);
                            //         }
                            //     }
                                // }
                            // }

                        }
                    }
                }
                
            }
            /* Forward analysis to see which load instructions can call instructions reach */
            {            
                /* If a instruction can reach a target CallInst in calls */
                std::unordered_map<Instruction *, bool> in;
                std::unordered_map<Instruction *, bool> out;
                /* Init result */
                for (Instruction *ci : calls[AI]) {
                    out[ci] = true;
                }
                // for (auto si : stores_to_instr[AI]) {
                //     in[si] = false;
                // }
                bool changed = true, cur_changed = false;


                while (changed) {
                    changed = false;
                    for (BasicBlock &BB : F) {
                        for (auto it = BB.begin(), e = BB.end(); it != e; it++) {
                            cur_changed = false;
                            Instruction *I = &*it;
                            if (in[I] != out[I]) {
                                if (std::find(stores_to_instr[AI].begin(),
                                              stores_to_instr[AI].end(), I)
                                            == stores_to_instr[AI].end() &&
                                    std::find(loads_to_instr[AI].begin(),
                                              loads_to_instr[AI].end(), I)
                                            == loads_to_instr[AI].end()) {
                                    out[I] = out[I] | in[I];
                                }
                            }

                            bool in_res;
                            Instruction *ni;

                            if (I == BB.getTerminator()) {


                                if (isa<BranchInst>(I)) {
                                    BranchInst *BI = dyn_cast<BranchInst>(I);
                                    for (unsigned int i = 0;
                                        i < BI->getNumSuccessors(); i++) {
                                        BasicBlock *n = BI->getSuccessor(i);
                                        ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<LoadInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (out[I] && !in[ni]) {
                                            in[ni] = true;
                                            cur_changed = true;
                                        }
                                    }
                                } else if (isa<SwitchInst>(I)) {
                                    SwitchInst *SI = dyn_cast<SwitchInst>(I);
                                    for (unsigned int i = 0;
                                        i < SI->getNumSuccessors(); i++) {
                                        BasicBlock *n = SI->getSuccessor(i);
                                        ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<LoadInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (out[I] && !in[ni]) {
                                            in[ni] = true;
                                            cur_changed = true;
                                        }
                                    }
                                } else if (isa<IndirectBrInst>(I)) {
                                    IndirectBrInst *IBI =
                                        dyn_cast<IndirectBrInst>(I);
                                    for (unsigned int i = 0;
                                        i < IBI->getNumSuccessors(); i++) {
                                        BasicBlock *n = IBI->getSuccessor(i);
                                        ni = &n->front();
                                        while (ni != n->getTerminator() &&
                                            !(isa<LoadInst>(ni) ||
                                                isa<CallInst>(ni))) {
                                            ni = nextInst(ni);
                                        }
                                        if (out[I] && !in[ni]) {
                                            in[ni] = true;
                                            cur_changed = true;
                                        }
                                    }
                                } else if (isa<ReturnInst>(I)) {

                                } else if (isa<UnreachableInst>(I)) {

                                } else {
                                    DEBUG_MSG(errs() << "Unknown: " << *I << "\n");
                                }

                            } else if (isa<LoadInst>(I) || isa<StoreInst>(I) || isa<CallInst>(I)) {

                                ni = I;
                                do {
                                    ni = nextInst(ni);
                                } while (
                                    ni != BB.getTerminator() &&
                                    !(isa<LoadInst>(ni) || isa<StoreInst>(I) || isa<CallInst>(ni)));
                                assert(ni);

                                in_res = in[ni];
                                if (in_res)
                                    continue;
                                    

                                // DEBUG_MSG(errs() << "Current: " << *I << ", Next: " << *ni << ", Live: " << (out[I]? "true":"false" ) << (in[ni]? " true":" false" ) << "\n");
                                if (out[I] && !in[ni]) {
                                    in[ni] = true;
                                    cur_changed = true;
                                }

                            } else {
                                continue;
                            }

                            /* Update if anything changes */
                            if (cur_changed) {
                                changed = true;
                                // DEBUG_MSG(errs() << *ni << " == " << *AI << "\n");
                                if (std::find(loads_to_instr[AI].begin(),
                                            loads_to_instr[AI].end(),
                                            ni) != loads_to_instr[AI].end()) {
                                    loads.insert(cast<LoadInst>(ni));
                                    // DEBUG_MSG(errs() << "Adding\n");
                                }
                            }
                        }
                    }
                }
                
            }

        }
        return false;
    }

    bool getFunctionLiveness(Function &F) {

        in.clear();
        out.clear();

        /* Definitions: store instructions that write to stack addresses */
        std::unordered_map<Instruction *, AllocaInst *> defs;
        /* Uses: load instructions that read from stack addresses */
        std::unordered_map<Instruction *, AllocaInst *> uses;
        /* References: call instructions that have stack addresses as reference
         */
        std::unordered_map<Instruction *, std::set<AllocaInst *>> refs;
        bool changed = true;

        /* Init solution */
        for (BasicBlock &BB : F) {

            for (Instruction &Inst : BB) {

                Instruction *I = &Inst;
                if (isa<StoreInst>(I)) {
                    StoreInst *SI = dyn_cast<StoreInst>(I);

                    if (SI && SI->getPointerOperand() &&
                        SI->getPointerOperand()->getType()->isPointerTy()) {
                        AllocaInst *AI = getStackPtr(SI->getPointerOperand());
                        if (AI) {
                            defs[I] = AI;
                        }
                    }
                } else if (isa<LoadInst>(I)) {
                    LoadInst *LI = dyn_cast<LoadInst>(I);

                    if (LI->getPointerOperand()
                            ->getType()
                            ->getPointerElementType()
                            ->isPointerTy()) {

                        AllocaInst *AI = getStackPtr(LI->getPointerOperand());
                        if (AI) {
                            uses[I] = AI;
                        }
                    }
                } else if (isa<CallInst>(I)) {
                    CallInst *CI = dyn_cast<CallInst>(I);

                    Function *F = CI->getCalledFunction();

                    if (!F)
                        continue;

                    StringRef fname = F->getName();

                    if (fname.find("llvm.") == 0 || fname.find("clang.") == 0) {
                        continue;
                    }

                    for (Value *V : CI->arg_operands()) {
                        AllocaInst *AI = getStackPtr(V);

                        if (AI) {
                            refs[I].insert(AI);
                        }
                    }
                }
            }
        }

        /*
         * Liveness algorithm
         * https://www.cs.colostate.edu/~mstrout/CS553/slides/lecture03.pdf
         * Repeat until converge
         */
        while (changed) {
            changed = false;
            for (BasicBlock &BB : F) {
                for (auto it = BB.rbegin(), e = BB.rend(); it != e; it++) {
                    Instruction *I = &*it;
                    std::set<AllocaInst *> in_res;
                    std::set<AllocaInst *> out_res;

                    in_res = out[I];
                    for (AllocaInst *AI : refs[I]) {
                        in_res.erase(AI);
                    }
                    in_res.erase(defs[I]);
                    in_res.insert(uses[I]);

                    if (I == BB.getTerminator()) {

                        if (isa<BranchInst>(I)) {
                            BranchInst *BI = dyn_cast<BranchInst>(I);
                            for (unsigned int i = 0; i < BI->getNumSuccessors();
                                 i++) {
                                BasicBlock *n = BI->getSuccessor(i);
                                Instruction *ni = &n->front();
                                while (ni != n->getTerminator() &&
                                       !(isa<StoreInst>(ni) ||
                                         isa<LoadInst>(ni) ||
                                         isa<CallInst>(ni))) {
                                    ni = nextInst(ni);
                                }
                                for (AllocaInst *AI : in[ni]) {
                                    out_res.insert(AI);
                                }
                            }
                        } else if (isa<SwitchInst>(I)) {
                            SwitchInst *SI = dyn_cast<SwitchInst>(I);
                            for (unsigned int i = 0; i < SI->getNumSuccessors();
                                 i++) {
                                BasicBlock *n = SI->getSuccessor(i);
                                Instruction *ni = &n->front();
                                while (ni != n->getTerminator() &&
                                       !(isa<StoreInst>(ni) ||
                                         isa<LoadInst>(ni) ||
                                         isa<CallInst>(ni))) {
                                    ni = nextInst(ni);
                                }
                                for (AllocaInst *AI : in[ni]) {
                                    out_res.insert(AI);
                                }
                            }
                        } else if (isa<IndirectBrInst>(I)) {
                            IndirectBrInst *IBI = dyn_cast<IndirectBrInst>(I);
                            for (unsigned int i = 0;
                                 i < IBI->getNumSuccessors(); i++) {
                                BasicBlock *n = IBI->getSuccessor(i);
                                Instruction *ni = &n->front();
                                while (ni != n->getTerminator() &&
                                       !(isa<StoreInst>(ni) ||
                                         isa<CallInst>(ni))) {
                                    ni = nextInst(ni);
                                }
                                for (AllocaInst *AI : in[ni]) {
                                    out_res.insert(AI);
                                }
                            }
                        } else if (isa<ReturnInst>(I)) {

                        } else if (isa<UnreachableInst>(I)) {

                        } else {
                        }

                    }
                    // else {
                    else if (isa<BranchInst>(I) || isa<SwitchInst>(I) ||
                             isa<UnreachableInst>(I) || isa<StoreInst>(I) ||
                             isa<LoadInst>(I) || isa<CallInst>(I)) {
                        Instruction *ni = I;
                        do {
                            ni = nextInst(ni);
                            //} while (false);
                        } while (ni != BB.getTerminator() &&
                                 !(isa<StoreInst>(ni) || isa<LoadInst>(ni) ||
                                   isa<CallInst>(ni)));
                        assert(ni);
                        out_res = in[ni];
                    } else {
                        continue;
                    }

                    /* Update if anything changes */
                    if (in_res != in[I]) {
                        in[I] = in_res;
                        changed = true;
                    }

                    if (out_res != out[I]) {
                        out[I] = out_res;
                        changed = true;
                    }
                }
            }
        }

        return false;
    }
};

/*
 * Helper class for call graph analysis
 * We conservatively anlysis if a call instr would free any claimed dynamic mem
 */
struct CallGraphAnalysis {
    std::set<std::string> external;
    std::set<std::string> may_free = {"free", "realloc", "_ZdlPv", "_ZdaPv"};
    std::set<std::string> not_free = {"malloc", "_Znwm", "calloc"};
    std::list<Function *> calls;

    bool has_free_call(Function *F) {

        if (!F)
            return true;

        std::string fname = F->getName();

        for (Function *Func : calls)
            if (F == Func) {
                return false;
            }

        if (may_free.find(fname) != may_free.end()) {
            return true;
        }
        if (not_free.find(fname) != not_free.end()) {
            return false;
        }
        if (external.find(fname) != external.end()) {
            return true;
        }

        /* External function */
        if (F->empty()) {
            if (fname == "regptr" || fname == "deregptr" ||
                fname == "stack_regptr" || fname == "global_hook" ||
                fname == "voidcallstack" || fname == "checkstackvar")
                return false;
            if (fname.find("llvm.") == 0 || fname.find("clang.") == 0)
                return false;
            external.insert(fname);
            return true;
        }

        calls.push_back(F);
        for (BasicBlock &B : *F)
            for (Instruction &Ins : B) {
                Instruction *I = &Ins;
                if (isa<CallInst>(I)) {
                    Function *CF = cast<CallInst>(I)->getCalledFunction();
                    if (F != CF)
                        if (has_free_call(CF)) {

                            may_free.insert(fname);
                            calls.pop_back();
                            return true;
                        }
                }
            }

        calls.pop_back();
        not_free.insert(fname);
        return false;
    }
};

/*
 * Class that examines important local pointer variables
 * And register them to suppress them from lift to LLVM reg
 */
struct HeapExpoStackTracker : public FunctionPass,
                              public CallGraphAnalysis,
                              public LivenessAnalysis {
    static char ID;
    std::set<AllocaInst *> stack_ptrs;
    std::map<AllocaInst *, DIVariable *> stack_vars;
    std::vector<CallInst *> calls_to_instr;
    std::unordered_map<AllocaInst *, std::vector<StoreInst *>> stores_to_instr;
    std::unordered_map<AllocaInst *, std::vector<LoadInst *>> loads_to_instr;

    HeapExpoStackTracker() : FunctionPass(ID) {}

    virtual bool runOnFunction(Function &F) {

        DEBUG_MSG(errs() << "HeapExpo: ");
        DEBUG_MSG(errs().write_escaped(demangleName(F.getName())) << '\n');

        // DEBUG_MSG(errs() << F << "\n");
        if (M != F.getParent()) {
            M = F.getParent();
            // initialized = false;
        }

        // if (!initialized)
        //     initialize(M);

        Func = &F;
        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
            Instruction *I = &*i;
            // DEBUG_MSG(errs() << "Instruction: " << *I << "\n");
            if (isa<StoreInst>(I)) {
                DEBUG_MSG(errs() << "Store instruction: " << *I << "\n");
                StoreInst *SI = dyn_cast<StoreInst>(I);

                if (SI->getPointerOperand()->getType()->isPointerTy()) {

                    AllocaInst *AI = getStackPtr(SI->getPointerOperand());
                    if (AI) {

                        stack_ptrs.insert(AI);

                        if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                            DEBUG_MSG(errs() << "Value is a nullptr\n");
                            // stack_store_instr_cnt ++;
                        } else {
                            DEBUG_MSG(errs() << "Value is a ptr\n");
                            // DEBUG_MSG(errs() << "AI: " << *AI << " Store: " << *SI << "\n");
                            stores_to_instr[AI].push_back(SI);
                        }
                    }
                }
            } else if (isa<LoadInst>(I)) {

                DEBUG_MSG(errs() << "Load instruction: " << *I << "\n");
                LoadInst *LI = dyn_cast<LoadInst>(I);
                if (LI->getType()->isPointerTy()) {
                    AllocaInst *AI = getStackPtr(LI->getPointerOperand());
                    if (AI) {
                        stack_ptrs.insert(AI);
                        DEBUG_MSG(errs() << "Value is a ptr\n");        
                        loads_to_instr[AI].push_back(LI);
                    }
                }


            } else if (isa<CallInst>(I)) {

                DEBUG_MSG(errs() << "Call instruction: " << *I << "\n");

                CallInst *CI = dyn_cast<CallInst>(I);

                if (!CI)
                    continue;

                Function *F = CI->getCalledFunction();
                if (!F)
                    continue;

                StringRef fname = F->getName();

                /*
                 * No InstrinsicInst Class
                 * Use function name to detect intrinsic functions
                 */
                if (F->getName().find("llvm.") == 0 ||
                    F->getName().find("clang.") == 0) {

                    /* Use declare instrinsic to Hook AllocaInst with DIVariable
                     */
                    if (fname == "llvm.dbg.declare") {

                        AllocaInst *AI = nullptr;
                        DIVariable *V = nullptr;
                        Metadata *meta0 =
                            cast<MetadataAsValue>(CI->getOperand(0))
                                ->getMetadata();
                        if (isa<ValueAsMetadata>(meta0)) {
                            Value *v0 =
                                cast<ValueAsMetadata>(meta0)->getValue();
                            if (isa<AllocaInst>(v0)) {
                                AI = cast<AllocaInst>(v0);
                            }
                        }

                        Metadata *meta1 =
                            cast<MetadataAsValue>(CI->getOperand(1))
                                ->getMetadata();
                        if (isa<DIVariable>(meta1))
                            V = cast<DIVariable>(meta1);

                        if (AI && V) {
                            stack_vars[AI] = V;
                        }
                    }

                    continue;
                }

                if (fname == "regptr" || fname == "deregptr" ||
                    fname == "voidcallstack" || fname == "checkstackvar")
                    continue;

                if (has_free_call(F))
                    calls_to_instr.push_back(CI);
            }
        }

        /* Liveness */
        getFunctionLiveness(F);

        std::set<AllocaInst *> aset;
        std::map<AllocaInst *, std::set<CallInst *>> live_calls;
        for (CallInst *CI : calls_to_instr) {

            // bool v = false;

            for (AllocaInst *AI : stack_ptrs) {
                if (out.find(CI) != out.end() &&
                    out[CI].find(AI) != out[CI].end()) {

                    /* No need to check in production */
                    // instrCheck(CI, AI, stack_vars[AI]);
                    aset.insert(AI);
                    live_calls[AI].insert(CI);
                    // v = true;
                }
            }

            // if (v)
            //     instrVoid(CI);
        }

        // DEBUG_MSG(errs() << "Alloca instructions to track:\n");
        // for (AllocaInst *AI : aset) {
        //     DEBUG_MSG(errs() << *AI << "\n");
        // }
        // DEBUG_MSG(errs() << "Calls to instrument:\n");
        // for (CallInst *CI : calls_to_instr) {
        //     DEBUG_MSG(errs() << *CI << "\n");
        // }
        // DEBUG_MSG(errs() << "Live calls:\n");
        // for (auto p: live_calls) {
        //     DEBUG_MSG(errs() << *p.first << " [");
        //     for (auto v: p.second) {
        //         DEBUG_MSG(errs() << *v << ", ");
        //     }
        //     DEBUG_MSG(errs() << "]\n");
        // }

        getStoreInstructionLiveness(F, live_calls, aset, stores_to_instr, loads_to_instr);

        for (StoreInst *SI : stores) {
            // instrStackReg(SI);
            DEBUG_MSG(errs() << "Volatilize store: " << *SI << "\n");
            SI->setVolatile(true);
            // stack_store_instr_cnt++;
        }
        for (LoadInst *LI : loads) {
            DEBUG_MSG(errs() << "Volatilize load: " << *LI << "\n");
            LI->setVolatile(true);
        }

        /*
        for (AllocaInst *AI : aset) {
            for (StoreInst *SI : stores_to_instr[AI]) {
                // instrStackReg(SI);
                DEBUG_MSG(errs() << *SI << "\n");
                SI->setVolatile(true);
                // stack_store_instr_cnt++;
            }
            for (LoadInst *LI : loads_to_instr[AI]) {
                DEBUG_MSG(errs() << *LI << "\n");
                LI->setVolatile(true);
                // stack_store_instr_cnt++;
            }
        }
         */

        stack_ptrs.clear();
        calls_to_instr.clear();
        return false;
    }
};

char HeapExpoStackTracker::ID = 0;
static RegisterPass<HeapExpoStackTracker> X("HeapExpoStack",
                                            "HeapExpo Stack Pass",
                                            false /* Only looks at CFG */,
                                            false /* Analysis Pass */);

static void registerMyPassEarly(const PassManagerBuilder &,
                                legacy::PassManagerBase &PM) {
    PM.add(new HeapExpoStackTracker());
}

/* EarlyAsPossible is enabled with opt level 0 */
static RegisterStandardPasses
    RegisterMyPassEarly(PassManagerBuilder::EP_EarlyAsPossible,
                        registerMyPassEarly);
