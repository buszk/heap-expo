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

static __attribute__((unused)) std::string demangleName(std::string input) {
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

                                out_res = in[ni];

                            } else {
                                continue;
                            }

                            /* Update if anything changes */
                            if (out_res != out[I]) {
                                out[I] = out_res;
                                if (std::find(stores_to_instr[AI].begin(),
                                            stores_to_instr[AI].end(),
                                            I) != stores_to_instr[AI].end()) {
                                    stores.insert(cast<StoreInst>(I));
                                }
                                changed = true;
                            }

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
    std::set<std::string> may_free = {"_ZdlPv", "_ZdaPv", "brk", "cfree", "free", "freeaddrinfo", "freelocale", "mremap", "munmap", "obstack_free", "realloc", "xdr_free", "EVP_MD_CTX_cleanup", "EC_GROUP_free", "EC_POINT_clear_free", "DH_free", "EVP_CIPHER_CTX_cleanup", "MD5_Final", "RSA_free", "BIO_free", "BN_CTX_free", "DSA_SIG_free", "EVP_PKEY_free", "EC_POINT_free", "CRYPTO_free", "HMAC_CTX_cleanup", "ECDSA_SIG_free", "HMAC_Final", "BN_free", "BN_clear_free", "SHA1_Final", "llvm.lifetime.end", "__cxa_free_exception"};
    std::set<std::string> not_free = {"a64l", "abort", "abs", "accept", "access", "acct", "acos", "acosf", "acosh", "acoshf", "acoshl", "acosl", "addch", "addchnstr", "addchstr", "addmntent", "addnstr", "addseverity", "addstr", "adjtime", "adjtimex", "adler32", "aio_cancel", "aio_cancel64", "aio_error", "aio_error64", "aio_fsync", "aio_fsync64", "aio_init", "aio_read", "aio_read64", "aio_return", "aio_return64", "aio_suspend", "aio_suspend64", "aio_write", "aio_write64", "alarm", "alloca", "alphasort", "alphasort64", "argp_error", "argp_failure", "argp_help", "argp_parse", "argp_state_help", "argp_usage", "argz_add", "argz_add_sep", "argz_append", "argz_count", "argz_create", "argz_create_sep", "argz_delete", "argz_extract", "argz_insert", "argz_next", "argz_replace", "argz_stringify", "asctime", "asctime_r", "asin", "asinf", "asinh", "asinhf", "asinhl", "asinl", "asprintf", "__assert_fail", "atan", "atan2", "atan2f", "atan2l", "atanf", "atanh", "atanhf", "atanhl", "atanl", "atexit", "atof", "atoi", "atol", "atoll", "attr_get", "attroff", "attr_off", "attron", "attr_on", "attrset", "attr_set", "authnone_create", "backtrace", "backtrace_symbols", "backtrace_symbols_fd", "basename", "baudrate", "bcmp", "bcopy", "beep", "bind", "bindresvport", "bindtextdomain", "bind_textdomain_codeset", "bkgd", "bkgdset", "border", "box", "bsd_signal", "bsearch", "btowc", "bzero", "cabs", "cabsf", "cabsl", "cacos", "cacosf", "cacosh", "cacoshf", "cacoshl", "cacosl", "calloc", "can_change_color", "canonicalize_file_name", "carg", "cargf", "cargl", "casin", "casinf", "casinh", "casinhf", "casinhl", "casinl", "catan", "catanf", "catanh", "catanhf", "catanhl", "catanl", "catclose", "catgets", "catopen", "cbc_crypt", "cbreak", "cbrt", "cbrtf", "cbrtl", "ccos", "ccosf", "ccosh", "ccoshf", "ccoshl", "ccosl", "ceil", "ceilf", "ceill", "cexp", "cexpf", "cexpl", "cfgetispeed", "cfgetospeed", "cfmakeraw", "cfsetispeed", "cfsetospeed", "cfsetspeed", "chdir", "chgat", "chmod", "chown", "chroot", "cimag", "cimagf", "cimagl", "clear", "clearenv", "clearerr", "clearerr_unlocked", "clearok", "clnt_create", "clnt_pcreateerror", "clnt_perrno", "clnt_perror", "clnt_spcreateerror", "clnt_sperrno", "clnt_sperror", "clock", "clock_getcpuclockid", "clock_getres", "clock_gettime", "clock_nanosleep", "clock_settime", "clog", "clog10", "clog10f", "clog10l", "clogf", "clogl", "close", "closedir", "closelog", "clrtobot", "clrtoeol", "color_content", "color_set", "compress", "compress2", "compressBound", "confstr", "conj", "conjf", "conjl", "connect", "copysign", "copysignf", "copysignl", "copywin", "cos", "cosf", "cosh", "coshf", "coshl", "cosl", "cpow", "cpowf", "cpowl", "cproj", "cprojf", "cprojl", "crc32", "creal", "crealf", "creall", "creat", "creat64", "crypt", "crypt_r", "csin", "csinf", "csinh", "csinhf", "csinhl", "csinl", "csqrt", "csqrtf", "csqrtl", "ctan", "ctanf", "ctanh", "ctanhf", "ctanhl", "ctanl", "ctermid", "ctime", "ctime_r", "__ctype_b_loc", "__ctype_get_mb_cur_max", "__ctype_tolower_loc", "__ctype_toupper_loc", "curs_set", "cuserid", "__cxa_atexit", "daemon", "dcgettext", "dcngettext", "deflate", "deflateBound", "deflateCopy", "deflateEnd", "deflateInit_", "deflateInit2_", "deflateParams", "deflateReset", "deflateSetDictionary", "def_prog_mode", "def_shell_mode", "delay_output", "delch", "del_curterm", "deleteln", "delscreen", "delwin", "derwin", "DES_FAILED", "des_setparity", "dgettext", "difftime", "dirfd", "dirname", "div", "dladdr", "dlclose", "dlerror", "dlopen", "dlsym", "dngettext", "doupdate", "drand48", "drand48_r", "drem", "dremf", "dreml", "DTTOIF", "dup", "dup2", "duplocale", "dupwin", "ecb_crypt", "echo", "echochar", "ecvt", "ecvt_r", "encrypt", "encrypt_r", "endfsent", "endgrent", "endhostent", "endmntent", "endnetent", "endnetgrent", "endprotoent", "endpwent", "endservent", "endutent", "endutxent", "endwin", "envz_add", "envz_entry", "envz_get", "envz_merge", "envz_strip", "erand48", "erand48_r", "erase", "erasechar", "erf", "erfc", "erfcf", "erfcl", "erff", "erfl", "err", "__errno_location", "error", "error_at_line", "errx", "execl", "execle", "execlp", "execv", "execve", "execvp", "_Exit", "exit", "_exit", "exp", "exp10", "exp10f", "exp10l", "exp2", "exp2f", "exp2l", "expf", "expl", "expm1", "expm1f", "expm1l", "fabs", "fabsf", "fabsl", "__fbufsize", "fchdir", "fchmod", "fchown", "fclose", "fcloseall", "fcntl", "fcvt", "fcvt_r", "fdatasync", "fdim", "fdimf", "fdiml", "fdopen", "fdopendir", "feclearexcept", "fedisableexcept", "feenableexcept", "fegetenv", "fegetexcept", "fegetexceptflag", "fegetround", "feholdexcept", "feof", "feof_unlocked", "feraiseexcept", "ferror", "ferror_unlocked", "fesetenv", "fesetexceptflag", "fesetround", "fetestexcept", "feupdateenv", "fflush", "fflush_unlocked", "ffs", "fgetc", "fgetc_unlocked", "fgetgrent", "fgetgrent_r", "fgetpos", "fgetpos64", "fgetpwent", "fgetpwent_r", "fgets", "fgets_unlocked", "fgetwc", "fgetwc_unlocked", "fgetws", "fgetws_unlocked", "fileno", "fileno_unlocked", "filter", "finite", "__finite", "finitef", "__finitef", "finitel", "__finitel", "flash", "__flbf", "flock", "flockfile", "floor", "floorf", "floorl", "flushinp", "_flushlbf", "fma", "fmaf", "fmal", "fmax", "fmaxf", "fmaxl", "fmemopen", "fmin", "fminf", "fminl", "fmod", "fmodf", "fmodl", "fmtmsg", "fnmatch", "fopen", "fopen64", "fopencookie", "fork", "forkpty", "fpathconf", "__fpclassify", "__fpclassifyf", "__fpending", "fprintf", "__fpurge", "fputc", "fputc_unlocked", "fputs", "fputs_unlocked", "fputwc", "fputwc_unlocked", "fputws", "fputws_unlocked", "fread", "__freadable", "__freading", "fread_unlocked", "freopen", "freopen64", "frexp", "frexpf", "frexpl", "fscanf", "fseek", "fseeko", "fseeko64", "__fsetlocking", "fsetpos", "fsetpos64", "fstat", "fstat64", "fstatfs", "fstatfs64", "fstatvfs", "fstatvfs64", "fsync", "ftell", "ftello", "ftello64", "ftime", "ftok", "ftruncate", "ftruncate64", "ftrylockfile", "ftw", "ftw64", "funlockfile", "futimes", "fwide", "fwprintf", "__fwritable", "fwrite", "fwrite_unlocked", "__fwriting", "fwscanf", "__fxstat", "__fxstat64", "gai_strerror", "gamma", "gammaf", "gammal", "gcvt", "getaddrinfo", "getauxval", "get_avphys_pages", "getbkgd", "getc", "getch", "getchar", "getchar_unlocked", "getcontext", "get_crc_table", "getc_unlocked", "get_current_dir_name", "getcwd", "getdate", "getdate_r", "getdelim", "getdomainnname", "getegid", "getenv", "geteuid", "getfsent", "getfsfile", "getfsspec", "getgid", "getgrent", "getgrent_r", "getgrgid", "getgrgid_r", "getgrnam", "getgrnam_r", "getgrouplist", "getgroups", "gethostbyaddr", "gethostbyaddr_r", "gethostbyname", "gethostbyname2", "gethostbyname2_r", "gethostbyname_r", "gethostent", "gethostid", "gethostname", "getitimer", "getline", "getloadavg", "getlogin", "getlogin_r", "getmntent", "getmntent_r", "getnameinfo", "getnetbyaddr", "getnetbyname", "getnetent", "getnetgrent", "getnetgrent_r", "get_nprocs", "get_nprocs_conf", "getnstr", "getopt", "getopt_long", "getopt_long_only", "getpagesize", "__getpagesize", "getpass", "getpeername", "getpgid", "__getpgid", "getpgrp", "get_phys_pages", "getpid", "getppid", "getpriority", "getprotobyname", "getprotobynumber", "getprotoent", "getpt", "getpwent", "getpwent_r", "getpwnam", "getpwnam_r", "getpwuid", "getpwuid_r", "getrlimit", "getrlimit64", "getrusage", "getservbyname", "getservbyport", "getservent", "getsid", "getsockname", "getsockopt", "getstr", "getsubopt", "gettext", "gettimeofday", "getuid", "getumask", "getutent", "getutent_r", "getutid", "getutid_r", "getutline", "getutline_r", "getutmp", "getutmpx", "getutxent", "getutxid", "getutxline", "getw", "getwc", "getwchar", "getwchar_unlocked", "getwc_unlocked", "getwd", "getwin", "glob", "glob64", "globfree", "globfree64", "gmtime", "gmtime_r", "grantpt", "gsignal", "gtty", "gzclose", "gzdopen", "gzeof", "gzerror", "gzflush", "gzgetc", "gzgets", "gzopen", "gzprintf", "gzputc", "gzputs", "gzread", "gzrewind", "gzseek", "gzsetparams", "gztell", "gzwrite", "halfdelay", "has_colors", "has_ic", "has_il", "hasmntopt", "hcreate", "hcreate_r", "hdestroy", "hdestroy_r", "__h_errno_location", "hline", "hsearch", "hsearch_r", "htonl", "htons", "hypot", "hypotf", "hypotl", "iconv", "iconv_close", "iconv_open", "idcok", "idlok", "if_freenameindex", "if_indextoname", "if_nameindex", "if_nametoindex", "IFTODT", "ilogb", "ilogbf", "ilogbl", "imaxabs", "imaxdiv", "immedok", "inch", "inchnstr", "inchstr", "index", "inet_addr", "inet_aton", "inet_lnaof", "inet_makeaddr", "inet_netof", "inet_network", "inet_ntoa", "inet_ntop", "inet_pton", "inflate", "inflateEnd", "inflateInit_", "inflateInit2_", "inflateReset", "inflateSetDictionary", "inflateSync", "inflateSyncPoint", "init_color", "initgroups", "init_pair", "initscr", "initstate", "initstate_r", "innetgr", "innstr", "insch", "insdelln", "insertln", "insnstr", "insque", "insstr", "instr", "intrflush", "ioctl", "_IO_feof", "_IO_getc", "_IO_putc", "_IO_puts", "isalnum", "isalpha", "isascii", "isatty", "isblank", "iscntrl", "isdigit", "isendwin", "isgraph", "isinf", "__isinf", "isinff", "__isinff", "isinfl", "__isinfl", "is_linetouched", "islower", "isnan", "__isnan", "isnanf", "__isnanf", "isnanl", "__isnanl", "isprint", "ispunct", "isspace", "isupper", "iswalnum", "iswalpha", "iswblank", "iswcntrl", "iswctype", "iswdigit", "iswgraph", "is_wintouched", "iswlower", "iswprint", "iswpunct", "iswspace", "iswupper", "iswxdigit", "isxdigit", "j0", "j0f", "j0l", "j1", "j1f", "j1l", "jn", "jnf", "jnl", "jrand48", "jrand48_r", "key_decryptsession", "keyname", "keypad", "kill", "killchar", "killpg", "l64a", "labs", "lchown", "lcong48", "lcong48_r", "ldexp", "ldexpf", "ldexpl", "ldiv", "leaveok", "lfind", "lgamma", "lgammaf", "lgammaf_r", "lgammal", "lgammal_r", "lgamma_r", "__libc_current_sigrtmax", "__libc_current_sigrtmin", "__libc_start_main", "link", "lio_listio", "lio_listio64", "listen", "llabs", "lldiv", "llrint", "llrintf", "llrintl", "llround", "llroundf", "llroundl", "localeconv", "localtime", "localtime_r", "lockf", "lockf64", "log", "log10", "log10f", "log10l", "log1p", "log1pf", "log1pl", "log2", "log2f", "log2l", "logb", "logbf", "logbl", "logf", "login", "login_tty", "logl", "logout", "logwtmp", "longjmp", "_longjmp", "longname", "lrand48", "lrand48_r", "lrint", "lrintf", "lrintl", "lround", "lroundf", "lroundl", "lsearch", "lseek", "lseek64", "lstat", "lstat64", "lutimes", "__lxstat", "__lxstat64", "madvise", "makecontext", "mallinfo", "malloc", "mallopt", "matherr", "mblen", "mbrlen", "mbrtowc", "mbsinit", "mbsnrtowcs", "mbsrtowcs", "mbstowcs", "mbtowc", "mcheck", "memalign", "memccpy", "memchr", "memcmp", "memcpy", "memfrob", "memmem", "memmove", "mempcpy", "__mempcpy", "memrchr", "memset", "meta", "mkdir", "mkdtemp", "mkfifo", "mknod", "mkstemp", "mkstemp64", "mktemp", "mktime", "mlock", "mlockall", "mmap", "mmap64", "modf", "modff", "modfl", "mount", "move", "mprobe", "mprotect", "mrand48", "mrand48_r", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "mtrace", "munlock", "munlockall", "muntrace", "mvaddch", "mvaddchnstr", "mvaddchstr", "mvaddnstr", "mvaddstr", "mvchgat", "mvcur", "mvdelch", "mvderwin", "mvgetch", "mvgetnstr", "mvgetstr", "mvhline", "mvinch", "mvinchnstr", "mvinchstr", "mvinnstr", "mvinsch", "mvinsnstr", "mvinsstr", "mvinstr", "mvprintw", "mvscanw", "mvvline", "mvwaddch", "mvwaddchnstr", "mvwaddchstr", "mvwaddnstr", "mvwaddstr", "mvwchgat", "mvwdelch", "mvwgetch", "mvwgetnstr", "mvwgetstr", "mvwhline", "mvwin", "mvwinch", "mvwinchnstr", "mvwinchstr", "mvwinnstr", "mvwinsch", "mvwinsnstr", "mvwinsstr", "mvwinstr", "mvwprintw", "mvwscanw", "mvwvline", "nan", "nanf", "nanl", "nanosleep", "napms", "nearbyint", "nearbyintf", "nearbyintl", "newlocale", "newpad", "newterm", "newwin", "nextafter", "nextafterf", "nextafterl", "nexttoward", "nexttowardf", "nexttowardl", "nftw", "nftw64", "ngettext", "nice", "nl", "nl_langinfo", "nocbreak", "nodelay", "noecho", "nonl", "noqiflush", "noraw", "notimeout", "nrand48", "nrand48_r", "ntohl", "ntohs", "ntp_adjtime", "ntp_gettime", "obstack_1grow", "obstack_1grow_fast", "obstack_alloc", "obstack_base", "obstack_blank", "obstack_blank_fast", "obstack_copy", "obstack_copy0", "obstack_finish", "obstack_grow", "obstack_grow0", "obstack_init", "obstack_int_grow", "obstack_int_grow_fast", "obstack_next_free", "obstack_object_size", "obstack_printf", "obstack_ptr_grow", "obstack_ptr_grow_fast", "obstack_room", "obstack_vprintf", "on_exit", "open", "open64", "opendir", "openlog", "open_memstream", "openpty", "overlay", "overwrite", "pair_content", "pam_acct_mgmt", "pam_authenticate", "pam_chauthtok", "pam_close_session", "pam_end", "pam_fail_delay", "pam_getenvlist", "pam_get_item", "pam_open_session", "pam_setcred", "pam_set_item", "pam_start", "pam_strerror", "parse_printf_format", "pathconf", "pause", "pclose", "pechochar", "perror", "pipe", "pmap_getport", "pmap_set", "pmap_unset", "pnoutrefresh", "poll", "popen", "posix_memalign", "posix_openpt", "pow", "pow10", "pow10f", "pow10l", "powf", "powl", "__ppc_get_timebase", "__ppc_get_timebase_freq", "__ppc_mdoio", "__ppc_mdoom", "__ppc_set_ppr_low", "__ppc_set_ppr_med", "__ppc_set_ppr_med_low", "__ppc_yield", "pread", "pread64", "prefresh", "printf", "printf_size", "printf_size_info", "printw", "psignal", "pthread_attr_destroy", "pthread_attr_getdetachstate", "pthread_attr_getguardsize", "pthread_attr_getinheritsched", "pthread_attr_getschedparam", "pthread_attr_getschedpolicy", "pthread_attr_getscope", "pthread_attr_getstack", "pthread_attr_getstackaddr", "pthread_attr_getstacksize", "pthread_attr_init", "pthread_attr_setdetachstate", "pthread_attr_setguardsize", "pthread_attr_setinheritsched", "pthread_attr_setschedparam", "pthread_attr_setschedpolicy", "pthread_attr_setscope", "pthread_attr_setstack", "pthread_attr_setstackaddr", "pthread_attr_setstacksize", "pthread_cancel", "_pthread_cleanup_pop", "_pthread_cleanup_push", "pthread_condattr_destroy", "pthread_condattr_getpshared", "pthread_condattr_init", "pthread_condattr_setpshared", "pthread_cond_broadcast", "pthread_cond_destroy", "pthread_cond_init", "pthread_cond_signal", "pthread_cond_timedwait", "pthread_cond_wait", "pthread_create", "pthread_detach", "pthread_equal", "pthread_exit", "pthread_getattr_default_np", "pthread_getconcurrency", "pthread_getschedparam", "pthread_getspecific", "pthread_join", "pthread_key_create", "pthread_key_delete", "pthread_kill", "pthread_mutexattr_destroy", "pthread_mutexattr_getpshared", "pthread_mutexattr_gettype", "pthread_mutexattr_init", "pthread_mutexattr_setpshared", "pthread_mutexattr_settype", "pthread_mutex_destroy", "pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock", "pthread_once", "pthread_rwlockattr_destroy", "pthread_rwlockattr_getpshared", "pthread_rwlockattr_init", "pthread_rwlockattr_setpshared", "pthread_rwlock_destroy", "pthread_rwlock_init", "pthread_rwlock_rdlock", "pthread_rwlock_timedrdlock", "pthread_rwlock_timedwrlock", "pthread_rwlock_tryrdlock", "pthread_rwlock_trywrlock", "pthread_rwlock_unlock", "pthread_rwlock_wrlock", "pthread_self", "pthread_setcancelstate", "pthread_setcanceltype", "pthread_setconcurrency", "pthread_setschedparam", "pthread_setschedprio", "pthread_setspecific", "pthread_sigmask", "pthread_testcancel", "ptsname", "ptsname_r", "putc", "putchar", "putchar_unlocked", "putc_unlocked", "putenv", "putp", "putpwent", "puts", "pututline", "pututxline", "putw", "putwc", "putwchar", "putwchar_unlocked", "putwc_unlocked", "putwin", "pwrite", "pwrite64", "qecvt", "qecvt_r", "qfcvt", "qfcvt_r", "qgcvt", "qiflush", "qsort", "raise", "rand", "random", "random_r", "rand_r", "raw", "rawmemchr", "__rawmemchr", "read", "readdir", "readdir64", "readdir64_r", "readdir_r", "readlink", "readv", "realpath", "recv", "recvfrom", "recvmsg", "redrawwin", "refresh", "regcomp", "regerror", "regexec", "regfree", "__register_atfork", "register_printf_function", "remainder", "remainderf", "remainderl", "remove", "remque", "remquo", "remquof", "remquol", "rename", "reset_prog_mode", "reset_shell_mode", "resetty", "restartterm", "rewind", "rewinddir", "rindex", "rint", "rintf", "rintl", "ripoffline", "rmdir", "round", "roundf", "roundl", "rpmatch", "savetty", "sbrk", "*sbrk", "scalb", "scalbf", "scalbl", "scalbln", "scalblnf", "scalblnl", "scalbn", "scalbnf", "scalbnl", "scandir", "scandir64", "scanf", "scanw", "sched_getaffinity", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setparam", "sched_setscheduler", "sched_yield", "scr_dump", "scr_init", "scrl", "scroll", "scrollok", "scr_restore", "scr_set", "secure_getenv", "seed48", "seed48_r", "seekdir", "select", "sem_close", "semctl", "sem_destroy", "semget", "sem_getvalue", "sem_init", "semop", "sem_open", "sem_post", "sem_timedwait", "sem_trywait", "sem_unlink", "sem_wait", "send", "sendmsg", "sendto", "setbuf", "setbuffer", "setcontext", "set_curterm", "setdomainname", "setegid", "setenv", "seteuid", "setfsent", "setgid", "setgrent", "setgroups", "sethostent", "sethostid", "sethostname", "setitimer", "_setjmp", "setkey", "setkey_r", "setlinebuf", "setlocale", "setlogmask", "setmntent", "setnetent", "setnetgrent", "setpgid", "setpgrp", "setpriority", "setprotoent", "setpwent", "setregid", "setreuid", "setrlimit", "setrlimit64", "setscrreg", "setservent", "setsid", "setsockopt", "setstate", "setstate_r", "set_term", "settimeofday", "setuid", "setupterm", "setutent", "setutxent", "setvbuf", "shmat", "shmctl", "shmdt", "shmget", "shm_open", "shm_unlink", "shutdown", "sigaction", "sigaddset", "sigaltstack", "sigandset", "sigblock", "sigdelset", "sigemptyset", "sigfillset", "sighold", "sigignore", "siginterrupt", "sigisemptyset", "sigismember", "siglongjmp", "signal", "signbit", "__signbit", "__signbitf", "signgam", "significand", "significandf", "significandl", "sigorset", "sigpause", "sigpending", "sigprocmask", "sigqueue", "sigrelse", "sigreturn", "sigset", "sigsetjmp", "__sigsetjmp", "sigsetmask", "sigstack", "sigsuspend", "sigtimedwait", "sigvec", "sigwait", "sigwaitinfo", "sin", "sincos", "sincosf", "sincosl", "sinf", "sinh", "sinhf", "sinhl", "sinl", "sleep", "slk_attroff", "slk_attron", "slk_attrset", "slk_attr_set", "slk_clear", "slk_color", "slk_init", "slk_label", "slk_noutrefresh", "slk_refresh", "slk_restore", "slk_set", "slk_touch", "snprintf", "sockatmark", "socket", "socketpair", "sprintf", "sqrt", "sqrtf", "sqrtl", "srand", "srand48", "srand48_r", "srandom", "srandom_r", "sscanf", "ssignal", "standend", "standout", "start_color", "stat", "stat64", "statfs", "statfs64", "statvfs", "statvfs64", "stime", "stpcpy", "__stpcpy", "stpncpy", "strcasecmp", "strcasestr", "strcat", "strchr", "strchrnul", "strcmp", "strcoll", "strcpy", "strcspn", "strdup", "__strdup", "strerror", "strerror_r", "strfmon", "strfry", "strftime", "strlen", "strncasecmp", "strncat", "strncmp", "strncpy", "strndup", "strnlen", "strpbrk", "strptime", "strrchr", "strsep", "strsignal", "strspn", "strstr", "strtod", "__strtod_internal", "strtof", "__strtof_internal", "strtoimax", "strtok", "__strtok_r", "strtok_r", "strtol", "strtold", "__strtold_internal", "__strtol_internal", "strtoll", "__strtoll_internal", "strtoq", "strtoul", "__strtoul_internal", "strtoull", "__strtoull_internal", "strtoumax", "strtouq", "strverscmp", "strxfrm", "stty", "subpad", "subwin", "svcerr_auth", "svcerr_decode", "svcerr_noproc", "svcerr_noprog", "svcerr_progvers", "svcerr_systemerr", "svcerr_weakauth", "svc_getreqset", "svc_register", "svc_run", "svc_sendreply", "svctcp_create", "svcudp_create", "swab", "swapcontext", "swprintf", "swscanf", "symlink", "sync", "syncok", "syscall", "sysconf", "__sysconf", "sysctl", "syslog", "system", "__sysv_signal", "sysv_signal", "tan", "tanf", "tanh", "tanhf", "tanhl", "tanl", "tcdrain", "tcflow", "tcflush", "tcgetattr", "tcgetpgrp", "tcgetsid", "tcsendbreak", "tcsetattr", "tcsetpgrp", "tdelete", "tdestroy", "telldir", "tempnam", "termattrs", "termname", "textdomain", "tfind", "tgamma", "tgammaf", "tgammal", "tgetent", "tgetflag", "tgetnum", "tgetstr", "tgoto", "tigetflag", "tigetnum", "tigetstr", "time", "timegm", "timelocal", "timeout", "timer_create", "timer_delete", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tmpfile", "tmpfile64", "tmpnam", "tmpnam_r", "toascii", "tolower", "_tolower", "touchline", "touchwin", "toupper", "_toupper", "towctrans", "towlower", "towupper", "tparm", "tputs", "trunc", "truncate", "truncate64", "truncf", "truncl", "tsearch", "ttyname", "ttyname_r", "twalk", "typeahead", "tzset", "ualarm", "ulimit", "umask", "umount", "umount2", "uname", "uncompress", "unctrl", "ungetc", "ungetch", "ungetwc", "unlink", "unlockpt", "unsetenv", "untouchwin", "updwtmp", "use_env", "uselocale", "usleep", "utime", "utimes", "utmpname", "utmpxname", "valloc", "vasprintf", "vdprintf", "verr", "verrx", "versionsort", "versionsort64", "vfork", "vfprintf", "vfscanf", "vfwprintf", "vfwscanf", "vidattr", "vidputs", "vlimit", "vline", "vprintf", "vscanf", "vsnprintf", "vsprintf", "vsscanf", "vswprintf", "vswscanf", "vsyslog", "vtimes", "vwarn", "vwarnx", "vwprintf", "vwprintw", "vw_printw", "vwscanf", "vwscanw", "vw_scanw", "waddch", "waddchnstr", "waddchstr", "waddnstr", "waddstr", "wait", "wait3", "wait4", "waitpid", "warn", "warnx", "wattr_get", "wattroff", "wattr_off", "wattron", "wattr_on", "wattrset", "wattr_set", "wbkgd", "wbkgdset", "wborder", "wchgat", "wclear", "wclrtobot", "wclrtoeol", "wcolor_set", "wcpcpy", "wcpncpy", "wcrtomb", "wcscasecmp", "wcscat", "wcschr", "wcschrnul", "wcscmp", "wcscoll", "wcscpy", "wcscspn", "wcsdup", "wcsftime", "wcslen", "wcsncasecmp", "wcsncat", "wcsncmp", "wcsncpy", "wcsnlen", "wcsnrtombs", "wcspbrk", "wcsrchr", "wcsrtombs", "wcsspn", "wcsstr", "wcstod", "__wcstod_internal", "wcstof", "__wcstof_internal", "wcstoimax", "wcstok", "wcstol", "wcstold", "__wcstold_internal", "__wcstol_internal", "wcstoll", "wcstombs", "wcstoq", "wcstoul", "__wcstoul_internal", "wcstoull", "wcstoumax", "wcstouq", "wcswcs", "wcswidth", "wcsxfrm", "wctob", "wctomb", "wctrans", "wctype", "wcursyncup", "wcwidth", "wdelch", "wdeleteln", "wechochar", "werase", "wgetch", "wgetnstr", "wgetstr", "whline", "winch", "winchnstr", "winchstr", "winnstr", "winsch", "winsdelln", "winsertln", "winsnstr", "winsstr", "winstr", "wmemchr", "wmemcmp", "wmemcpy", "wmemmove", "wmempcpy", "wmemset", "wmove", "wnoutrefresh", "wordexp", "wordfree", "wprintf", "wprintw", "wredrawln", "wrefresh", "write", "writev", "wscanf", "wscanw", "wscrl", "wsetscrreg", "wstandend", "wstandout", "wsyncdown", "wsyncup", "wtimeout", "wtouchln", "wvline", "xdr_accepted_reply", "xdr_array", "xdr_bool", "xdr_bytes", "xdr_callhdr", "xdr_callmsg", "xdr_char", "xdr_double", "xdr_enum", "xdr_float", "xdr_int", "xdr_long", "xdrmem_create", "xdr_opaque", "xdr_opaque_auth", "xdr_pointer", "xdrrec_create", "xdrrec_eof", "xdr_reference", "xdr_rejected_reply", "xdr_replymsg", "xdr_short", "xdr_string", "xdr_u_char", "xdr_u_int", "xdr_u_long", "xdr_union", "xdr_u_short", "xdr_vector", "xdr_void", "xdr_wrapstring", "__xmknod", "__xstat", "__xstat64", "y0", "y0f", "y0l", "y1", "y1f", "y1l", "yn", "ynf", "ynl", "zError", "zlibVersion", "__mbstowcs_alias", "__realpath_alias", "__ptsname_r_chk_warn", "__xmknodat", "__openat_alias", "__open_2", "__stpncpy_alias", "__builtin_strchr", "__gets_chk", "__fread_chk", "__fxstatat", "__fread_alias", "__wctomb_alias", "__wcstombs_chk_warn", "__builtin_expect", "__mbstowcs_chk_warn", "__fgets_alias", "__builtin___sprintf_chk", "__stpncpy_chk", "__ptsname_r_alias", "__fread_chk_warn", "__mbstowcs_chk", "__wctomb_chk", "__builtin___memset_chk", "__open_too_many_args", "__builtin___memmove_chk", "__fread_unlocked_chk_warn", "__realpath_chk", "__vfprintf_chk", "__overflow", "__builtin___vsprintf_chk", "__openat_2", "__printf_chk", "__fread_unlocked_alias", "__fread_unlocked_chk", "__builtin_object_size", "__wcstombs_alias", "__uflow", "__gets_warn", "__fgets_chk_warn", "__builtin_va_arg_pack_len", "__builtin___strcat_chk", "__wcstombs_chk", "__fprintf_chk", "__open_alias", "__builtin___strcpy_chk", "__builtin___strncat_chk", "__builtin___strncpy_chk", "__builtin___memcpy_chk", "__fgets_chk", "__openat_too_many_args", "__builtin___snprintf_chk", "__ptsname_r_chk", "__builtin___vsnprintf_chk", "__builtin_alloca", "__builtin_va_arg", "__builtin_memcpy", "__builtin_va_start", "__builtin_va_end", "__getcwd_alias", "__builtin_fabsf", "__read_chk", "__ttyname_r_chk_warn", "__readlink_chk_warn", "__builtin_fabsl", "__readlinkat_chk", "__getgroups_chk_warn", "__gethostname_chk_warn", "__gethostname_chk", "__getwd_warn", "__getdomainname_chk", "__builtin_atan2l", "__builtin_fabs", "__confstr_alias", "__ttyname_r_chk", "__read_chk_warn", "__readlinkat_chk_warn", "__getlogin_r_alias", "__confstr_chk", "__getdomainname_chk_warn", "__getlogin_r_chk_warn", "__readlink_chk", "__readlink_alias", "__getcwd_chk", "__getgroups_alias", "__getcwd_chk_warn", "__ttyname_r_alias", "__read_alias", "__getwd_chk", "__getdomainname_alias", "__gethostname_alias", "__readlinkat_alias", "__getlogin_r_chk", "__getgroups_chk", "__confstr_chk_warn", "__builtin_strspn", "__fdelt_chk", "__builtin_strlen", "__builtin_strcmp", "__builtin_huge_val", "regptr", "regptr_nr", "unregisterstackptrs", "registerstackptrs", "registerptr", "registerptrobj", "sendfile", "getusershell", "endusershell", "setusershell", "updwtmpx", "updwtmp", "logwtmp", "getspnam", "__builtin_strncpy", "__fxstatat64", "ptrace", "prctl", "__open64_2", "BIO_new_mem_buf", "BN_value_one", "ERR_error_string", "BN_new", "EVP_PKEY_get1_RSA", "BN_rand", "EC_KEY_get0_private_key", "DSA_do_sign", "DSA_new", "EC_METHOD_get_field_type", "EC_GROUP_method_of", "RSA_generate_key_ex", "BIO_s_mem", "HMAC_Update", "PEM_write_RSAPrivateKey", "EC_GROUP_new_by_curve_name", "EC_POINT_mul", "EVP_CIPHER_CTX_init", "RAND_seed", "PEM_write_DSA_PUBKEY", "EVP_DigestFinal_ex", "EVP_CIPHER_CTX_set_app_data", "PEM_read_PUBKEY", "BN_mod_word", "BN_rshift1", "MD5_Init", "AES_set_encrypt_key", "BN_CTX_new", "PEM_write_bio_DSAPrivateKey", "EC_KEY_generate_key", "EVP_CIPHER_CTX_iv_length", "EC_KEY_new_by_curve_name", "BN_div", "BN_num_bits", "RAND_bytes", "EVP_CIPHER_CTX_get_app_data", "PEM_read_RSAPublicKey", "EC_POINT_new", "DSA_generate_key", "BN_CTX_get", "EC_KEY_set_public_key", "setresgid", "BIO_ctrl", "BN_lshift", "BN_mod_exp", "BN_bin2bn", "SSLeay_version", "SSLeay", "EVP_DigestInit_ex", "BN_is_bit_set", "DSA_generate_parameters_ex", "EC_KEY_get0_public_key", "BN_sub", "BN_dec2bn", "EVP_PKEY_get1_EC_KEY", "BN_CTX_start", "EVP_CIPHER_CTX_ctrl", "DH_generate_key", "PEM_write_bio_RSAPrivateKey", "ERR_get_error", "EVP_PKEY_get1_DSA", "EC_KEY_set_asn1_flag", "BIO_new", "EC_GROUP_cmp", "EVP_CipherInit", "BN_hex2bn", "EC_GROUP_get_curve_name", "AES_encrypt", "BN_mod_mul", "EVP_DigestUpdate", "EC_POINT_cmp", "RSA_size", "RSA_get_default_method", "BN_set_word", "PEM_write_RSA_PUBKEY", "RSA_set_ex_data", "PEM_write_RSAPublicKey", "BN_add", "EC_POINT_is_at_infinity", "HMAC_CTX_init", "BN_rand_range", "RSA_public_encrypt", "EC_POINT_get_affine_coordinates_GFp", "EVP_aes_128_cbc", "RAND_status", "EC_GROUP_get_order", "BN_bn2bin", "DH_new", "EVP_Cipher", "BN_cmp", "ECDSA_do_sign", "EVP_sha1", "BN_print_fp", "EC_GROUP_get_degree", "BN_rshift", "PEM_write_bio_ECPrivateKey", "RSA_new", "HMAC_Init", "EVP_CIPHER_CTX_set_key_length", "BN_bn2dec", "MD5_Update", "DH_compute_key", "BN_dup", "PEM_write_EC_PUBKEY", "EVP_MD_size", "EVP_PKEY_type", "BN_mod_sub", "EVP_bf_cbc", "EC_KEY_get0_group", "RSA_set_method", "__open64_alias", "__fgets_unlocked_chk_warn", "__realpath_chk_warn", "__obstack_printf_chk", "__recvfrom_alias", "__obstack_vprintf_chk", "__builtin_strcspn", "__openat64_alias", "_getlong", "__fgets_unlocked_alias", "__vdprintf_chk", "__wcstoll_internal", "__dprintf_chk", "__syslog_chk", "__strsep_g", "__builtin___mempcpy_chk", "__recv_alias", "setresuid", "_getshort", "__res_query", "__asprintf_chk", "__recv_chk", "__open64_too_many_args", "__pread64_chk_warn", "__wcstoull_internal", "__fgets_unlocked_chk", "__openat64_2", "__pread64_alias", "__dn_expand", "__builtin_strpbrk", "__openat64_too_many_args", "__recvfrom_chk", "__pread64_chk", "__getdelim", "__vasprintf_chk", "__recvfrom_chk_warn", "vhangup", "__recv_chk_warn", "__builtin___stpcpy_chk", "__vsyslog_chk", "__res_state", "epoll_ctl", "epoll_create1", "dup3", "getservbyname_r", "accept4", "getifaddrs", "pthread_yield", "epoll_wait", "pthread_mutexattr_setrobust_np", "__builtin_strncat", "pthread_mutexattr_setprotocol", "freeifaddrs", "pthread_mutex_consistent_np", "sendfile64", "setspent", "endspent", "__builtin_mempcpy", "hstrerror", "capget", "capset", "pcre_compile", "SHA1_Init", "SHA1_Update", "pcre_exec", "posix_fadvise", "openat", "pcre_fullinfo", "pcre_study", "llvm.dbg.value", "llvm.bswap.i16", "llvm.dbg.declare", "llvm.eh.typeid.for", "llvm.lifetime.start", "llvm.memcpy.p0i8.p0i8.i32", "llvm.memcpy.p0i8.p0i8.i64", "llvm.memmove.p0i8.p0i8.i32", "llvm.memset.p0i8.i32", "llvm.umul.with.overflow.i32", "registerptr", "__cxa_allocate_exception", "__cxa_begin_catch", "__cxa_end_catch"
    };
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
struct StackVolatileOptimizer : public FunctionPass,
                              public CallGraphAnalysis,
                              public LivenessAnalysis {
    static char ID;
    std::set<AllocaInst *> stack_ptrs;
    std::map<AllocaInst *, DIVariable *> stack_vars;
    std::vector<CallInst *> calls_to_instr;
    std::unordered_map<AllocaInst *, std::vector<StoreInst *>> stores_to_instr;
    std::unordered_map<AllocaInst *, std::vector<LoadInst *>> loads_to_instr;

    StackVolatileOptimizer() : FunctionPass(ID) {}

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
            if (isa<StoreInst>(I)) {
                StoreInst *SI = dyn_cast<StoreInst>(I);
		//if (SI->getMetadata("heapexpovolatile"))
		    SI->setVolatile(false);
	    }
	    else if (isa<LoadInst>(I)) {
                LoadInst *LI = dyn_cast<LoadInst>(I);
		//if (LI->getMetadata("heapexpovolatile"))
		    LI->setVolatile(false);
	    }
	}
	errs() << F << "\n";
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
#if 0
	return false;
#endif

        /* Liveness */
        getFunctionLiveness(F);

        std::set<AllocaInst *> aset;
        std::map<AllocaInst *, std::set<CallInst *>> live_calls;
        for (CallInst *CI : calls_to_instr) {

            for (AllocaInst *AI : stack_ptrs) {
                if (out.find(CI) != out.end() &&
                    out[CI].find(AI) != out[CI].end()) {

                    aset.insert(AI);
                    live_calls[AI].insert(CI);
                }
            }

        }

        getStoreInstructionLiveness(F, live_calls, aset, stores_to_instr, loads_to_instr);

        for (StoreInst *SI : stores) {
            DEBUG_MSG(errs() << "Volatilize store: " << *SI << "\n");
            SI->setVolatile(true);
        }
        for (LoadInst *LI : loads) {
            DEBUG_MSG(errs() << "Volatilize load: " << *LI << "\n");
            LI->setVolatile(true);
        }

        stack_ptrs.clear();
        calls_to_instr.clear();
        return false;
    }
};

char StackVolatileOptimizer::ID = 0;
static RegisterPass<StackVolatileOptimizer> X("stackvolatileoptimizer",
                                            "HeapExpo Stack Pass",
                                            false /* Only looks at CFG */,
                                            false /* Analysis Pass */);

