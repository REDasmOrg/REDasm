#include "vb_analyzer.h"
#include "vb_components.h"
#include "../pe.h"

#define VB_POINTER(T, address) m_peformat->pointer<T>(m_peformat->offset(address))
#define HAS_OPTIONAL_INFO(objdescr, objinfo) (objdescr.lpObjectInfo + sizeof(VBObjectInfo) != objinfo->base.lpConstants)
#define VB_METHODNAME(pubobj, control, method) (pubobj + "_" + control + "_" + method)

namespace REDasm {

VBAnalyzer::VBAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures): PEAnalyzer(disassembler, signatures)
{
    m_peformat = NULL;
    m_vbheader = NULL;
    m_vbprojinfo = NULL;
    m_vbobjtable = NULL;
    m_vbobjtreeinfo = NULL;
    m_vbpubobjdescr = NULL;
}

void VBAnalyzer::analyze(ListingDocument *document)
{
    /*
    SymbolTable* symboltable = document->symbols();
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
    */
}

void VBAnalyzer::disassembleTrampoline(u32 eventva, const std::string& name, ListingDocument *document)
{
    /*
    if(!eventva)
        return;

    InstructionPtr instruction = this->m_disassembler->disassembleInstruction(eventva); // Disassemble trampoline

    if(instruction->mnemonic == "sub")
    {
        this->disassembleTrampoline(instruction->endAddress(), name, document); // Jump follows...
        return;
    }

    if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
    {
        this->m_disassembler->disassemble(instruction->target());
        this->m_disassembler->symbolTable()->createFunction(instruction->target(), name);
    }
    */
}

void VBAnalyzer::decompileObject(ListingDocument *document, const VBPublicObjectDescriptor &pubobjdescr)
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
                                                                 component->events[j]), document);
    }
}

void VBAnalyzer::decompile(ListingDocument *document, SymbolPtr thunrtdata)
{
    if(!thunrtdata)
        return;

    this->m_peformat = reinterpret_cast<const PeFormat*>(document->format());
    this->m_vbheader = VB_POINTER(VBHeader, thunrtdata->address);
    this->m_vbprojinfo = VB_POINTER(VBProjectInfo, this->m_vbheader->lpProjectData);
    this->m_vbobjtable = VB_POINTER(VBObjectTable, this->m_vbprojinfo->lpObjectTable);
    this->m_vbobjtreeinfo = VB_POINTER(VBObjectTreeInfo, this->m_vbobjtable->lpObjectTreeInfo);
    this->m_vbpubobjdescr = VB_POINTER(VBPublicObjectDescriptor, this->m_vbobjtable->lpPubObjArray);

    for(size_t i = 0; i < this->m_vbobjtable->wTotalObjects; i++)
        this->decompileObject(document, this->m_vbpubobjdescr[i]);
}

} // namespace REDasm
