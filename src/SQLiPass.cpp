#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/FileSystem.h"

using namespace llvm;

namespace {

struct HelloSQLiPass : public PassInfoMixin<HelloSQLiPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
};

} 

static bool isInputSource(Function *F) {
    if (!F) return false;

    StringRef Name = F->getName();

    // Standard input (cin >> var)
    if (Name.contains("_ZStrs") ||      // std::operator>>
        Name.contains("_ZNSirs"))       // std::istream::operator>>
        return true;

    // Standard getline
    if (Name.contains("_ZSt7getline"))  // std::getline
        return true;

    // C-style input
    if (Name == "scanf" || 
        Name == "fscanf" || 
        Name == "gets" || 
        Name == "fgets")
        return true;

    // Environment/Args
    if (Name == "getenv")
        return true;

    return false;
}

static bool isSink(Function *F) {
    if (!F) return false;

    StringRef Name = F->getName();

    // Custom/Mock sink
    if (Name.contains("exec_query"))
        return true;

    // Common DB APIs
    if (Name == "mysql_query" || 
        Name == "mysql_real_query" ||
        Name == "sqlite3_exec" ||
        Name == "PQexec")
        return true;
        
    return false;
}

static bool isSanitizer(Function *F) {
    if (!F) return false;

    StringRef Name = F->getName();

    // Standard sanitization and escaping functions
    if (Name.contains("sanitize_input") ||
        Name.contains("escape_string") ||
        Name == "mysql_real_escape_string" ||
        Name == "PQescapeString" ||
        Name == "sqlite3_mprintf")
        return true;

    return false;
}

static std::string extractConstantString(Value *V) {
    if (!V) return "";
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
        if (CE->getOpcode() == Instruction::GetElementPtr) {
            V = CE->getOperand(0);
        }
    } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
        V = GEP->getPointerOperand();
    }

    if (auto *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->hasInitializer()) {
            Constant *Init = GV->getInitializer();
            if (auto *DataArray = dyn_cast<ConstantDataArray>(Init)) {
                if (DataArray->isString()) {
                    return DataArray->getAsString().str();
                } else if (DataArray->isCString()) {
                    return DataArray->getAsCString().str();
                }
            } else if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
                if (CDS->isString()) {
                    return CDS->getAsString().str();
                }
            }
        }
    }
    return "";
}

#include <set>
#include <map>
#include <vector>
#include <cctype>

PreservedAnalyses HelloSQLiPass::run(Module &M, ModuleAnalysisManager &) {
    errs() << "=== SQLi Detection Pass ===\n";

    // Inter-procedural analysis
    std::set<Value*> TaintedValues;
    std::map<Value*, std::string> KnownStrings;
    std::set<Instruction*> PatternDetected;
    bool Changed = true;

    // 1. Identify Sources (Seed the taint)
    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *CI = dyn_cast<CallBase>(&I)) {
                     Function *Callee = CI->getCalledFunction();
                     if (Callee && isInputSource(Callee)) {
                         for (unsigned i = 0; i < CI->arg_size(); ++i) {
                             if (CI->getArgOperand(i)->getType()->isPointerTy()) {
                                 TaintedValues.insert(CI->getArgOperand(i));
                                 errs() << "[TAINT] Source detected: " << Callee->getName() << ". Tainting arg " << i << " in " << F.getName() << "\n";
                             }
                         }
                     }
                }
            }
        }
    }

    // 2. Propagate Taint (Fixed-point iteration at Module level)
    while (Changed) {
        Changed = false;
        for (Function &F : M) {
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    
                    // A. Store: Tainted Val -> Tainted Ptr
                    if (auto *SI = dyn_cast<StoreInst>(&I)) {
                        Value *Val = SI->getValueOperand();
                        Value *Ptr = SI->getPointerOperand();
                        if (TaintedValues.count(Val) && !TaintedValues.count(Ptr)) {
                            TaintedValues.insert(Ptr);
                            Changed = true;
                        }
                    }

                    // B. Load: Tainted Ptr -> Tainted Val
                    if (auto *LI = dyn_cast<LoadInst>(&I)) {
                        Value *Ptr = LI->getPointerOperand();
                        if (TaintedValues.count(Ptr) && !TaintedValues.count(LI)) {
                            TaintedValues.insert(LI);
                            Changed = true;
                        }
                    }

                    // C. Call (String Operations)
                    if (auto *CI = dyn_cast<CallBase>(&I)) {
                         Function *Callee = CI->getCalledFunction();
                         if (!Callee) continue;
                         StringRef Name = Callee->getName();

                         // 1. String Concatenation (operator+)
                         if (Name.contains("_ZStpl")) { 
                             bool AnyArgTainted = false;
                             unsigned StartArg = CI->hasStructRetAttr() ? 1 : 0;
                             
                             // Pattern Check
                             for (unsigned i = StartArg; i < CI->arg_size(); ++i) {
                                 for (unsigned j = StartArg; j < CI->arg_size(); ++j) {
                                     if (i == j) continue;
                                     Value *ArgI = CI->getArgOperand(i);
                                     Value *ArgJ = CI->getArgOperand(j);
                                     bool taintedI = TaintedValues.count(ArgI);
                                     if (taintedI) {
                                         std::string strJ = extractConstantString(ArgJ);
                                         if (strJ.empty() && KnownStrings.count(ArgJ)) {
                                             strJ = KnownStrings[ArgJ];
                                         }
                                         if (!strJ.empty() && !PatternDetected.count(CI)) {
                                             std::string upperStr = strJ;
                                             for (auto &c : upperStr) c = toupper((unsigned char)c);
                                             if (upperStr.find("SELECT") != std::string::npos ||
                                                 upperStr.find("INSERT") != std::string::npos ||
                                                 upperStr.find("UPDATE") != std::string::npos ||
                                                 upperStr.find("DELETE") != std::string::npos ||
                                                 upperStr.find("WHERE") != std::string::npos ||
                                                 upperStr.find("FROM") != std::string::npos) {
                                                 errs() << "[PATTERN] Vulnerable SQL construction detected\n";
                                                 PatternDetected.insert(CI);
                                             }
                                         }
                                     }
                                 }
                                 
                                 if (TaintedValues.count(CI->getArgOperand(i))) {
                                     AnyArgTainted = true;
                                 }
                             }

                             if (AnyArgTainted) {
                                 Value *Dest = CI->hasStructRetAttr() ? CI->getArgOperand(0) : CI;
                                 if (!TaintedValues.count(Dest)) {
                                     TaintedValues.insert(Dest);
                                     Changed = true;
                                     errs() << "  [PROP] Taint spread via + to: " << Dest->getName() << "\n";
                                 }
                             }
                         }
                         // 2. String Assignment / Copying / Append
                         else if (Name.contains("basic_string") && 
                                 (Name.contains("aSE") || Name.contains("C1") || Name.contains("C2") || Name.contains("append") || Name.contains("pLE"))) {
                             if (CI->arg_size() >= 2) {
                                 Value *Dest = CI->getArgOperand(0);
                                 Value *Source = CI->getArgOperand(1);
                                 
                                 std::string literal = extractConstantString(Source);
                                 if (!literal.empty()) {
                                     if (KnownStrings.count(Dest)) {
                                         if (Name.contains("append") || Name.contains("pLE")) {
                                             KnownStrings[Dest] += literal;
                                         } else {
                                             KnownStrings[Dest] = literal;
                                         }
                                     } else {
                                         KnownStrings[Dest] = literal;
                                     }
                                 } else if (KnownStrings.count(Source)) {
                                     if (Name.contains("append") || Name.contains("pLE")) {
                                          if (KnownStrings.count(Dest)) KnownStrings[Dest] += KnownStrings[Source];
                                     } else {
                                         KnownStrings[Dest] = KnownStrings[Source];
                                     }
                                 }

                                 // Optional pattern match on append / +=
                                 bool HasPattern = false;
                                 if (Name.contains("append") || Name.contains("pLE")) {
                                     if (TaintedValues.count(Dest)) {
                                         std::string strSrc = extractConstantString(Source);
                                         if (strSrc.empty() && KnownStrings.count(Source)) strSrc = KnownStrings[Source];
                                         if (!strSrc.empty() && !PatternDetected.count(CI)) {
                                             std::string upperStr = strSrc;
                                             for (auto &c : upperStr) c = toupper(c);
                                             if (upperStr.find("SELECT") != std::string::npos ||
                                                 upperStr.find("INSERT") != std::string::npos ||
                                                 upperStr.find("UPDATE") != std::string::npos ||
                                                 upperStr.find("DELETE") != std::string::npos ||
                                                 upperStr.find("WHERE") != std::string::npos ||
                                                 upperStr.find("FROM") != std::string::npos) {
                                                 errs() << "[PATTERN] Vulnerable SQL construction detected\n";
                                                 PatternDetected.insert(CI);
                                                 HasPattern = true;
                                             }
                                         }
                                     } 
                                     if (!HasPattern && TaintedValues.count(Source)) {
                                         std::string strDest = KnownStrings.count(Dest) ? KnownStrings[Dest] : "";
                                         if (!strDest.empty() && !PatternDetected.count(CI)) {
                                             std::string upperStr = strDest;
                                             for (auto &c : upperStr) c = toupper(c);
                                             if (upperStr.find("SELECT") != std::string::npos ||
                                                 upperStr.find("INSERT") != std::string::npos ||
                                                 upperStr.find("UPDATE") != std::string::npos ||
                                                 upperStr.find("DELETE") != std::string::npos ||
                                                 upperStr.find("WHERE") != std::string::npos ||
                                                 upperStr.find("FROM") != std::string::npos) {
                                                 errs() << "[PATTERN] Vulnerable SQL construction detected\n";
                                                 PatternDetected.insert(CI);
                                             }
                                         }
                                     }
                                 }

                                 if (TaintedValues.count(Source) && !TaintedValues.count(Dest)) {
                                     TaintedValues.insert(Dest);
                                     Changed = true;
                                     errs() << "  [PROP] Taint spread via assign/append to: " << Dest->getName() << "\n";
                                 }
                             }
                         }
                         // 3. String Accessors (c_str, data)
                         else if (Name.contains("basic_string") && (Name.contains("c_str") || Name.contains("data"))) {
                             if (CI->arg_size() > 0) {
                                 Value *ThisPtr = CI->getArgOperand(0);
                                 if (KnownStrings.count(ThisPtr)) {
                                     KnownStrings[CI] = KnownStrings[ThisPtr];
                                 }
                                 if (TaintedValues.count(ThisPtr) && !TaintedValues.count(CI)) {
                                     TaintedValues.insert(CI);
                                     Changed = true;
                                     errs() << "  [PROP] Taint spread to .c_str() result\n";
                                 }
                             }
                         }
                         // 4 & 6. Inter-procedural: Bi-directional Argument Taint
                         if (!Callee->isDeclaration()) {
                             for (unsigned i = 0; i < CI->arg_size(); ++i) {
                                 Value *CallerArg = CI->getArgOperand(i);
                                 Argument *CalleeArg = Callee->getArg(i);
                                 if (!CalleeArg) continue;

                                 // String tracking
                                 if (KnownStrings.count(CallerArg)) {
                                     KnownStrings[CalleeArg] = KnownStrings[CallerArg];
                                 }

                                 if (TaintedValues.count(CallerArg) && !TaintedValues.count(CalleeArg)) {
                                     TaintedValues.insert(CalleeArg);
                                     Changed = true;
                                     errs() << "  [PROP-INTER] Taint spread to arg " << i << " of " << Callee->getName() << "\n";
                                 }
                                 
                                 // Taint from callee escapes via pointer arg
                                 if (TaintedValues.count(CalleeArg) && !TaintedValues.count(CallerArg)) {
                                     TaintedValues.insert(CallerArg);
                                     Changed = true;
                                     errs() << "  [PROP-INTER] Taint escapes via arg " << i << " of " << Callee->getName() << "\n";
                                 }
                             }

                             // 5. Inter-procedural: Tainted Return -> CallInst
                             for (BasicBlock &C_BB : *Callee) {
                                 for (Instruction &C_I : C_BB) {
                                     if (auto *RI = dyn_cast<ReturnInst>(&C_I)) {
                                         if (TaintedValues.count(RI->getReturnValue()) && !TaintedValues.count(CI)) {
                                             TaintedValues.insert(CI);
                                             Changed = true;
                                             errs() << "  [PROP-INTER] Taint returned from " << Callee->getName() << "\n";
                                         }
                                     }
                                 }
                             }
                         } else if (isSanitizer(Callee)) {
                             // --- WEEK 9: SANITIZER HEURISTICS ---
                             // If this is a known sanitizer function, untaint its arguments and its return value.
                             
                             // 1. Untaint arguments
                             for (unsigned i = 0; i < CI->arg_size(); ++i) {
                                 Value *Arg = CI->getArgOperand(i);
                                 if (TaintedValues.count(Arg)) {
                                     TaintedValues.erase(Arg);
                                     Changed = true;
                                     errs() << "  [SANITIZED] Untainting argument " << i << " of " << Callee->getName() << "\n";
                                 }
                             }
                             
                             // 2. Untaint the return value (the call instruction itself)
                             if (TaintedValues.count(CI)) {
                                 TaintedValues.erase(CI);
                                 Changed = true;
                                 errs() << "  [SANITIZED] Untainting return value from " << Callee->getName() << "\n";
                             }
                         }
                    }
                }
            }
        }
    }

    // 3. Check Sinks and Inject Warning
    bool IRChanged = false;
    LLVMContext &Ctx = M.getContext();
    PointerType *PtrTy = PointerType::getUnqual(Ctx);
    FunctionType *WarnFnTy = FunctionType::get(Type::getVoidTy(Ctx), {PtrTy}, false);
    FunctionCallee WarnFn = M.getOrInsertFunction("__sqli_warning", WarnFnTy);

    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (auto it = BB.begin(); it != BB.end(); ) {
                Instruction &I = *it++; // safe iteration
                if (auto *CI = dyn_cast<CallBase>(&I)) {
                     Function *Callee = CI->getCalledFunction();
                     if (Callee && isSink(Callee)) {
                         for (auto &Arg : CI->args()) {
                             if (TaintedValues.count(Arg.get())) {
                                 errs() << "VULNERABILITY DETECTED in function " << F.getName() << "\n";
                                 errs() << "  Sink: " << Callee->getName() << "\n";
                                 errs() << "  Instruction: " << I << "\n";
                                 
                                 IRBuilder<> Builder(CI);
                                 Builder.CreateCall(WarnFn, {Arg.get()});
                                 IRChanged = true;
                             }
                         }
                     }
                }
            }
        }
    }

    // 4. Generate CFG in JSON format
    std::error_code EC;
    raw_fd_ostream CFGFile("cfg_output.json", EC, sys::fs::OF_Text);
    if (!EC) {
        CFGFile << "{\n";
        bool FirstFunc = true;
        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            if (!FirstFunc) CFGFile << ",\n";
            FirstFunc = false;
            
            CFGFile << "  \"" << F.getName() << "\": {\n";
            CFGFile << "    \"BasicBlocks\": [\n";
            
            bool FirstBB = true;
            for (BasicBlock &BB : F) {
                if (!FirstBB) CFGFile << ",\n";
                FirstBB = false;
                
                CFGFile << "      {\n";
                CFGFile << "        \"Name\": \"";
                if (BB.hasName()) CFGFile << BB.getName();
                else BB.printAsOperand(CFGFile, false);
                CFGFile << "\",\n";
                
                CFGFile << "        \"Successors\": [";
                bool FirstSucc = true;
                for (BasicBlock *Succ : successors(&BB)) {
                    if (!FirstSucc) CFGFile << ", ";
                    FirstSucc = false;
                    CFGFile << "\"";
                    if (Succ->hasName()) CFGFile << Succ->getName();
                    else Succ->printAsOperand(CFGFile, false);
                    CFGFile << "\"";
                }
                CFGFile << "],\n";
                
                CFGFile << "        \"Instructions\": [";
                bool FirstInst = true;
                for (Instruction &I : BB) {
                    if (!FirstInst) CFGFile << ", ";
                    FirstInst = false;
                    std::string InstStr;
                    raw_string_ostream RSO(InstStr);
                    I.print(RSO);
                    
                    std::string EscapedInst;
                    for (char c : InstStr) {
                        if (c == '"') EscapedInst += "\\\"";
                        else if (c == '\\') EscapedInst += "\\\\";
                        else if (c == '\n') EscapedInst += "\\n";
                        else if (c == '\t') EscapedInst += "\\t";
                        else EscapedInst += c;
                    }
                    
                    bool isTainted = TaintedValues.count(&I);
                    if (!isTainted) {
                        for (Value *Op : I.operands()) {
                            if (TaintedValues.count(Op)) {
                                isTainted = true;
                                break;
                            }
                        }
                    }
                    
                    int lineNum = -1;
                    if (const llvm::DebugLoc &Loc = I.getDebugLoc()) {
                        lineNum = Loc.getLine();
                    }

                    CFGFile << "\n          { \"text\": \"" << EscapedInst << "\", \"tainted\": " << (isTainted ? "true" : "false") << ", \"line\": " << lineNum << " }";
                }
                CFGFile << "\n        ]\n";
                CFGFile << "      }";
            }
            CFGFile << "\n    ]\n";
            CFGFile << "  }";
        }
        CFGFile << "\n}\n";
        CFGFile.close();
    } else {
        errs() << "Error opening cfg_output.json for writing: " << EC.message() << "\n";
    }

    return IRChanged ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "HelloSQLiPass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name,
                   ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "hello-sqli") {
                        MPM.addPass(HelloSQLiPass());
                        return true;
                    }
                    return false;
                });
        }};
}
