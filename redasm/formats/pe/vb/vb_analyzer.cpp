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

void VBAnalyzer::analyze()
{
    SymbolPtr entrypoint = m_document->documentEntry();

    if(!entrypoint)
        return;

    auto it = m_document->instructionItem(entrypoint->address);

    if(it == m_document->end())
        return;

    const InstructionPtr& pushinstruction = m_document->instruction((*it)->address);
    const InstructionPtr& callinstruction = m_document->instruction((*++it)->address);

    if(!pushinstruction->is(InstructionTypes::Push) && !callinstruction->is(InstructionTypes::Call))
        return;

    SymbolPtr thunrtdata = m_document->symbol(pushinstruction->operands[0].u_value);

    if(thunrtdata)
        m_document->lock(thunrtdata->address, "thunRTData", SymbolTypes::Data);

    this->decompile(thunrtdata);
    PEAnalyzer::analyze();
}

void VBAnalyzer::disassembleTrampoline(address_t eventva, const std::string& name)
{
    if(!eventva)
        return;

    InstructionPtr instruction = m_disassembler->disassembleInstruction(eventva); // Disassemble trampoline

    if(instruction->mnemonic == "sub")
    {
        this->disassembleTrampoline(instruction->endAddress(), name); // Jump follows...
        return;
    }

    REDasm::status("Decoding " + name + " @ " + REDasm::hex(eventva));

    if(instruction->is(InstructionTypes::Jump) && instruction->hasTargets())
    {
        m_disassembler->disassemble(instruction->target());
        m_document->lock(instruction->target(), name, SymbolTypes::Function);
    }
}

void VBAnalyzer::decompileObject(const VBPublicObjectDescriptor &pubobjdescr)
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
            this->disassembleTrampoline(events[j], VB_METHODNAME(pubobjname, componentname, component->events[j]));
    }
}

void VBAnalyzer::decompile(SymbolPtr thunrtdata)
{
    if(!thunrtdata)
        return;

    m_peformat = reinterpret_cast<const PeFormat*>(m_document->format());
    m_vbheader = VB_POINTER(VBHeader, thunrtdata->address);
    m_vbprojinfo = VB_POINTER(VBProjectInfo, m_vbheader->lpProjectData);
    m_vbobjtable = VB_POINTER(VBObjectTable, m_vbprojinfo->lpObjectTable);
    m_vbobjtreeinfo = VB_POINTER(VBObjectTreeInfo, m_vbobjtable->lpObjectTreeInfo);
    m_vbpubobjdescr = VB_POINTER(VBPublicObjectDescriptor, m_vbobjtable->lpPubObjArray);

    for(size_t i = 0; i < m_vbobjtable->wTotalObjects; i++)
        this->decompileObject(m_vbpubobjdescr[i]);
}

} // namespace REDasm
