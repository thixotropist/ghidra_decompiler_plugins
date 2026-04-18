#include <string>
#include <sstream>
#include <set>
#include <algorithm>
#include <iterator>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"

#include "framework.hh"
#include "riscv.hh"
#include "vector_matcher.hh"
#include "vector_ops.hh"

namespace riscv_vector
{

VectorMatcher::VectorMatcher(ghidra::Funcdata& fData, ghidra::PcodeOp* initialVsetOp) :
    loopModel(fData, ghidra::pLogger->should_log(spdlog::level::trace)),
    data(fData),
    functionEditor(data, ghidra::inspector, ghidra::pLogger),
    codeSpace(nullptr),
    numElementsConstant(false),
    numElementsVariable(false),
    vectorRegistersMatch(false),
    multiplier(1),
    elementSize(0),
    vsetOp(initialVsetOp),
    vNumElem(nullptr),
    vNumPerLoop(nullptr),
    vLoad(nullptr),
    vLoadImm(nullptr),
    vStore(nullptr),
    trace(ghidra::pLogger->should_log(spdlog::level::trace)),
    info(ghidra::pLogger->should_log(spdlog::level::info))
{
    if (vsetOp == nullptr) return;
    // get basic info on the vsetop trigger
    const RiscvUserPcode* vsetInfo = RiscvUserPcode::getUserPcode(*vsetOp);
    numElementsConstant = vsetInfo->isVseti;
    numElementsVariable = vsetInfo->isVset;
    // we only want to trigger on two classes of vector ops
    if (!(vsetInfo->isVseti || vsetInfo->isVset)) return;
    multiplier = vsetInfo->multiplier;
    elementSize = vsetInfo->elementSize;
    if (vsetOp->numInput() < 2)
    {
        ghidra::pLogger->warn("Found a vsetOp at 0x{0:x}:{1:x} with no Varnodes",
            vsetOp->getAddr().getOffset(), vsetOp->getTime());
        return;
    }
    vNumElem = vsetOp->getIn(1);
    // determine if we have a loop and if so, where does it start and stop
    loopBlock = vsetOp->getParent();
    loopModel.analyze(vsetOp);
    // terminate construction if this vset op doesn't start a loop
    if (!loopModel.loopFound) return;
    // Follow dependencies of phi nodes within the loop to identify
    // source and destination pointer registers and the counter register
    collect_loop_registers();
    // show traits we have deduced
    ghidra::pLogger->info("Summary of traits:\n"
        "\tVector stanza begins at 0x{0:x}\n"
        "\telementSize = {1:d}\n"
        "\tmultiplier = {2:d}\n"
        "\tcode size = 0x{3:x}",
        loopModel.firstAddr, elementSize, multiplier, loopModel.lastAddr - loopModel.firstAddr);
    ghidra::pLogger->info("\n"
        "\tNumber of loop vector opcodes = {0:d}\n"
        "\tNumber of Phi nodes affected by loop = {1:d}\n"
        "\tNumber of arithmetic ops = {2:d}",
        loopModel.vectorOps.size(), loopModel.phiNodesAffectedByLoop.size(),
        loopModel.scalarOps.size());
    ghidra::pLogger->info("\n"
        "\tNumber of elements is constant = {0:s}\n"
        "\tNumber of elements is variable = {1:s}\n"
        "\tFound unexpected Ghidra opcode = {2:s}\n"
        "\tFound unexpected vector opcode = {3:s}\n"
        "\tFound unexpected user pcodes = {4:s}",
        numElementsConstant ? "true" : "false",
        numElementsVariable ? "true" : "false",
        (loopModel.otherScalarOps.size() > 0) ? "true" : "false",
        (loopModel.unhandledVectorOps.size() > 0) ? "true" : "false",
        (loopModel.otherUserPcodes.size() > 0) ? "true" : "false");
    ghidra::pLogger->info("\n\tFound simple flow structure = {0:s}\n"
        "\tFound vector registers match = {1:s}",
        loopModel.simpleFlowStructure ? "true" : "false",
        vectorRegistersMatch ? "true" : "false");
    ghidra::pLogger->info("\n"
        "\tNumber of elements varnode identified = {0:s}\n"
        "\tNumber of elements per loop varnode identified = {1:s}\n"
        "\tVector load address varnode identified = {2:s}\n"
        "\tVector store address varnode identified = {3:s}",
        vNumElem != nullptr ? "true" : "false",
        vNumPerLoop != nullptr ? "true" : "false",
        vLoad != nullptr ? "true" : "false",
        vStore != nullptr ? "true" : "false");
    loopModel.log();
}

VectorMatcher::~VectorMatcher()
{
    externalDependentOps.clear();
}

void VectorMatcher::collect_loop_registers()
{
    // use lists instead of vectors to allow for push_back inside iterative loops
    std::list<ghidra::Varnode *> dependentVarnodesInLoop;
    std::list<ghidra::Varnode *> dependentVarnodesOutsideLoop;
    std::list<ghidra::PcodeOp *> opsToVisit(loopModel.phiNodesAffectedByLoop.begin(), loopModel.phiNodesAffectedByLoop.end());
    ghidra::Varnode* vLoopStoreVn = nullptr;
    ghidra::Varnode* vectorNumElemVn = nullptr;
    ghidra::Varnode* vectorLoadRegisterVn = nullptr;
    ghidra::Varnode* vectorLoadAddrVn = nullptr;
    ghidra::Varnode* vectorStoreRegisterVn = nullptr;
    ghidra::Varnode* vectorStoreAddrVn = nullptr;
    std::stringstream ss;
    // For all Phi nodes affected by the loop determine the output register and its dependencies.
    for (auto op : opsToVisit)
    {
        if (trace)
        {
            op->printRaw(ss);
            ghidra::pLogger->trace("Examining context of: {0:s}", ss.str());
            ss.str("");
        }
        ghidra::Varnode* resultVn = op->getOut();
        // descendent ops with no return value need to be checked for content but not dependencies.
        bool opIsVoid = (resultVn == nullptr);
        ghidra::intb offset = op->getAddr().getOffset();
        bool isInsideLoop = (offset >= loopModel.firstAddr) && (offset <= loopModel.lastAddr);
        if (info && !opIsVoid)
        {
            std::string regName;
            ghidra::getRegisterName(resultVn, &regName);
            if (regName != "")
            {
                ghidra::pLogger->info("Tracing loop dependencies for register result {0:s} with register offset 0x{1:x}",
                                 regName, resultVn->getAddr().getOffset());
            }
            else
            {
                ghidra::pLogger->info("Tracing loop dependencies for non-register object with offset 0x{0:x}",
                                 resultVn->getAddr().getOffset());
            }
        }
        if (isInsideLoop)
        {
            ghidra::pLogger->trace("  Examining context of op inside the loop:");
            // if this is a vector op, identify the register assignments
            const RiscvUserPcode *opInfo = RiscvUserPcode::getUserPcode(*op);
            if (opInfo != nullptr)
            {
                if (opInfo->isVset)
                {
                    multiplier = opInfo->multiplier;
                    elementSize = opInfo->elementSize;
                    vectorNumElemVn = op->getIn(1);
                    vNumPerLoop = op->getOut();
                    if (vNumPerLoop == nullptr)
                    {
                        ghidra::pLogger->warn("Vector vset found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    ghidra::pLogger->trace("    Vset found: numElementsRegister=0x{0:x}",
                                      vectorNumElemVn->getOffset());
                }
                else if (opInfo->isLoad)
                {
                    vectorLoadRegisterVn = op->getOut();
                    if (vectorLoadRegisterVn == nullptr)
                    {
                        ghidra::pLogger->warn("Vector load found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    vectorLoadAddrVn = op->getIn(1);
                    ghidra::pLogger->trace("    Vload found at 0x{0:x}", op->getAddr().getOffset());
                    ghidra::pLogger->flush();
                    ghidra::pLogger->trace("    Vload register=0x{0:x}",
                                      vectorLoadRegisterVn->getOffset());
                }
                else if (opInfo->isStore)
                {
                    ghidra::pLogger->flush();
                    vectorStoreRegisterVn = op->getIn(1);
                    vectorStoreAddrVn = op->getIn(2);
                    vLoopStoreVn = op->getIn(2);
                    ghidra::pLogger->trace("    Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                                      vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
            }
            if (info && (resultVn != nullptr))
            {
                resultVn->printRaw(ss);
                ghidra::pLogger->trace("  inloop dependency: {0:s}", ss.str());
                ss.str("");
            }
            if (opIsVoid) continue;
            // Add new dependent ops to visit if this op has a known result *and* this op is inside the loop
            std::list<ghidra::PcodeOp *>::const_iterator begin = resultVn->beginDescend();
            std::list<ghidra::PcodeOp *>::const_iterator end = resultVn->endDescend();
            for (auto descendent = begin; descendent != end; ++descendent)
            {
                ghidra::PcodeOp *descendentOp = *descendent;
                if (trace)
                {
                    descendentOp->printRaw(ss);
                    ghidra::pLogger->trace("  Descendent op: {0:s}", ss.str());
                    ss.str("");
                }
                dependentVarnodesInLoop.push_back(resultVn);
                if (std::find(opsToVisit.begin(), opsToVisit.end(), descendentOp) == opsToVisit.end())
                    opsToVisit.push_back(descendentOp);
            }
        }
        else
        {
            ghidra::pLogger->trace("  Examining context of op outside the loop:");
            dependentVarnodesOutsideLoop.push_back(resultVn);
            if (std::find(externalDependentOps.begin(), externalDependentOps.end(), op) == externalDependentOps.end())
                externalDependentOps.push_back(op);
            if ((resultVn != nullptr) && info)
            {
                resultVn->printRaw(ss);
                ghidra::pLogger->trace("  exterior dependency to fix: {0:s}", ss.str());
                ss.str("");
            }
        }
    }
    // do load and store registers match?
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    // find the Phi node defining the loop registers
    for (auto op: loopModel.phiNodesAffectedByLoop)
    {
        if (trace)
        {
            op->printRaw(ss);
            ghidra::pLogger->trace("Checking PcodeOp for dependencies: {0:s}", ss.str());
            ss.str("");
        }
        ghidra::intb regOffset = op->getOut()->getAddr().getOffset();
        std::string regName;
        ghidra::getRegisterName(op->getOut(), &regName);
        ghidra::pLogger->trace("Searching for loop variables referring to register {0:s}", regName);
        if ((vectorNumElemVn != nullptr) && (!vectorNumElemVn->isConstant()) && (regOffset == vectorNumElemVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                ghidra::pLogger->trace("\tvNumElem identified as {0:s}", ss.str());
                ss.str("");
            }
            vNumElem = op->getOut();
        }
        else if ((vectorLoadAddrVn != nullptr) && (regOffset == vectorLoadAddrVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                ghidra::pLogger->trace("\tvLoadVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vLoad = op->getOut();
        }
        else if ((vectorStoreAddrVn != nullptr) && regOffset == vectorStoreAddrVn->getOffset())
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                ghidra::pLogger->trace("\tvStoreVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vStore = op->getOut();
        }
    }
}
}
