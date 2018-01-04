#include "vb_analyzer.h"
#include "vb_components.h"
#include "../pe.h"

#define VB_POINTER(T, address) _peformat->pointer<T>(_peformat->offset(address))
#define HAS_OPTIONAL_INFO(objdescr, objinfo) (objdescr.lpObjectInfo + sizeof(VBObjectInfo) != objinfo->base.lpConstants)
#define VB_METHODNAME(pubobj, control, method) (pubobj + "_" + control + "_" + method)

namespace REDasm {

VBAnalyzer::VBAnalyzer(DisassemblerFunctions *dfunctions, const SignatureFiles &signatures): PEAnalyzer(dfunctions, signatures)
{
    this->_peformat = NULL;
    this->_vbheader = NULL;
    this->_vbprojinfo = NULL;
    this->_vbobjtable = NULL;
    this->_vbobjtreeinfo = NULL;
    this->_vbpubobjdescr = NULL;
}

void VBAnalyzer::analyze(Listing &listing)
{
    SymbolTable* symboltable = listing.symbolTable();
    SymbolPtr entrypoint = symboltable->entryPoint();

    if(!entrypoint)
        return;

    auto it = listing.find(entrypoint->address);

    if(it == listing.end())
        return;

    const InstructionPtr& pushinstruction = *it;
    const InstructionPtr& callinstruction = *(++it);

    if(!pushinstruction->is(InstructionTypes::Push) && !callinstruction->is(InstructionTypes::Call))
        return;

    pushinstruction->comments.clear();
    listing.update(pushinstruction);
    listing.stopFunctionAt(callinstruction);

    SymbolPtr thunrtdata = symboltable->symbol(pushinstruction->operands[0].u_value);

    if(thunrtdata)
    {
        thunrtdata->type = SymbolTypes::Data;
        thunrtdata->lock();
        symboltable->update(thunrtdata, "thunRTData");
    }

    this->decompile(listing, thunrtdata);
    PEAnalyzer::analyze(listing);
}

void VBAnalyzer::disassembleTrampoline(u32 eventva, const std::string& name, Listing& listing)
{
    if(!eventva)
        return;

    InstructionPtr instruction = this->_disassembler->disassembleInstruction(eventva); // Disassemble trampoline

    if(instruction->mnemonic == "sub")
    {
        this->disassembleTrampoline(instruction->endAddress(), name, listing); // Jump follows...
        return;
    }

    if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
        this->_disassembler->disassembleFunction(instruction->target(), name);
}

void VBAnalyzer::decompileObject(Listing& listing, const VBPublicObjectDescriptor &pubobjdescr)
{
    if(!pubobjdescr.lpObjectInfo)
        return;

    VBObjectInfoOptional* objinfo = VB_POINTER(VBObjectInfoOptional, pubobjdescr.lpObjectInfo);

    // if lpConstants points to the address after it,
    // there's no optional object information
    if(!HAS_OPTIONAL_INFO(pubobjdescr, objinfo) || !objinfo->lpControls)
        return;

    std::string pubobjname = VB_POINTER(const char, pubobjdescr.lpszObjectName);
    VBControlInfo* ctrlinfo = VB_POINTER(VBControlInfo, objinfo->lpControls);

    for(size_t i = 0; i < objinfo->dwControlCount; i++)
    {
        const VBControlInfo& ctrl = ctrlinfo[i];
        const VBComponents::Component* component = VBComponents::get(VB_POINTER(GUID, ctrl.lpGuid));

        if(!component)
            continue;

        VBEventInfo* eventinfo = VB_POINTER(VBEventInfo, ctrl.lpEventInfo);
        std::string componentname = VB_POINTER(const char, ctrl.lpszName);
        u32* events = &eventinfo->lpEvents[0];

        for(size_t j = 0; j < component->events.size(); j++)
            this->disassembleTrampoline(events[j], VB_METHODNAME(pubobjname,
                                                                 componentname,
                                                                 component->events[j]), listing);
    }
}

void VBAnalyzer::decompile(Listing& listing, SymbolPtr thunrtdata)
{
    if(!thunrtdata)
        return;

    this->_peformat = reinterpret_cast<const PeFormat*>(listing.format());
    this->_vbheader = VB_POINTER(VBHeader, thunrtdata->address);
    this->_vbprojinfo = VB_POINTER(VBProjectInfo, this->_vbheader->lpProjectData);
    this->_vbobjtable = VB_POINTER(VBObjectTable, this->_vbprojinfo->lpObjectTable);
    this->_vbobjtreeinfo = VB_POINTER(VBObjectTreeInfo, this->_vbobjtable->lpObjectTreeInfo);
    this->_vbpubobjdescr = VB_POINTER(VBPublicObjectDescriptor, this->_vbobjtable->lpPubObjArray);

    for(size_t i = 0; i < this->_vbobjtable->wTotalObjects; i++)
        this->decompileObject(listing, this->_vbpubobjdescr[i]);
}

} // namespace REDasm
