#include "diagnostics.hh"
#include "riscv.hh"

namespace ghidra {

//
static bool varnode_tree_dumped = false;

void displayPcodeOp(PcodeOp& p, const string& label, bool descend)
{
    logFile << label << " PcodeOp: " ;
    p.printRaw(logFile);
    logFile << ";\tOpName: " << p.getOpName();
    logFile << ";\tAddr: 0x" << std::hex << p.getAddr().getOffset() << std::dec << std::endl;
    if (descend) {
        // display the input varnodes for this PcodeOp
        Varnode* v;
        for (auto inslot=0; inslot < p.numInput(); inslot++)
        {
            v = p.getIn(inslot);
            logFile << "\tInput Varnode[" << inslot << "]:";
            v->printRaw(logFile);
            logFile << ";\tflags = 0x" << std::hex << v->getFlags();
            logFile << ";\ttype = " << v->getType()->getName();
            logFile << ";\tspace = " << v->getSpace()->getName();
            logFile << ";\toffset = 0x" << v->getOffset() << std::dec << std::endl;
        }
        // display the output varnode and any descendents for this pcode op
        v = p.getOut();
        if (v != nullptr)
        {
            logFile << "\tOutput Varnode: ";
            v->printRaw(logFile);
            logFile << ";\tflags = 0x" << std::hex << v->getFlags();
            logFile << ";\ttype = " << v->getType()->getName();
            logFile << ";\tspace = " << v->getSpace()->getName();
            logFile << ";\toffset = 0x" << v->getOffset() << std::dec << std::endl;
            logFile << "\tDescendents:" << std::endl;
            std::list<PcodeOp*>::const_iterator enditer = v->endDescend();
            for (std::list<PcodeOp*>::const_iterator it=v->beginDescend();it!=enditer;++it)
            {
                logFile << "\t\t";
                (*it)->printRaw(logFile);
                logFile << std::endl;
            }
        }
    }
}

void displayVarnodeTree(Funcdata& data)
{
    if (!varnode_tree_dumped) {
        logFile << "Dumping the varnode tree" << std::endl;
        data.printVarnodeTree(logFile);
        logFile << std::endl;
        varnode_tree_dumped = true;
    }
}

void displayComment(const char* comment)
{
    logFile << comment << std::endl;
}
}