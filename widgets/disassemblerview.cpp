#include "disassemblerview.h"
#include "../hooks/disassemblerhooks.h"
#include "tabs/listingtab/listingtab.h"
#include "docks/listingmapdock/listingmapdock.h"

DisassemblerView::DisassemblerView(RDDisassembler* disassembler, QObject *parent) : QObject(parent), m_disassembler(disassembler)
{
    m_listingtab = new ListingTab(disassembler);
    m_listingmapdock = new ListingMapDock(m_listingtab->command());

    DisassemblerHooks::instance()->tab(m_listingtab);
    DisassemblerHooks::instance()->showFunctions(m_listingtab, Qt::LeftDockWidgetArea);
    DisassemblerHooks::instance()->showSegments(m_listingtab);
    DisassemblerHooks::instance()->showExports(m_listingtab);
    DisassemblerHooks::instance()->showImports(m_listingtab);
    DisassemblerHooks::instance()->showStrings(m_listingtab);
    DisassemblerHooks::instance()->dock(m_listingmapdock, Qt::RightDockWidgetArea);

    RDEvent_Subscribe(this, [](const RDEventArgs* e, void* userdata) {
        if(e->eventid != Event_CursorPositionChanged) return;
        DisassemblerView* thethis = reinterpret_cast<DisassemblerView*>(userdata);
        if(thethis->m_listingtab != DisassemblerHooks::instance()->currentTab()) return;
        DisassemblerHooks::instance()->statusAddress(thethis->m_listingtab->command());
    }, this);
}

DisassemblerView::~DisassemblerView() { RDEvent_Unsubscribe(this); }

RDDisassembler* DisassemblerView::disassembler() const { return m_disassembler; }
void DisassemblerView::dispose() { RD_Free(m_disassembler); this->deleteLater(); }
