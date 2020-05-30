#include "disassemblerview.h"
#include "../hooks/disassemblerhooks.h"
#include "tabs/listingtab/listingtab.h"
#include "docks/listingmapdock/listingmapdock.h"

DisassemblerView::DisassemblerView(RDDisassembler* disassembler, QObject *parent) : QObject(parent), m_disassembler(disassembler)
{
    ICommandTab* commantab = this->showListing();
    m_listingmapdock = new ListingMapDock(commantab->command());

    DisassemblerHooks::instance()->showFunctions(Qt::LeftDockWidgetArea);
    DisassemblerHooks::instance()->showSegments();
    DisassemblerHooks::instance()->showExports();
    DisassemblerHooks::instance()->showImports();
    DisassemblerHooks::instance()->showStrings();
    DisassemblerHooks::instance()->dock(m_listingmapdock, Qt::RightDockWidgetArea);
}

RDDisassembler* DisassemblerView::disassembler() const { return m_disassembler; }
void DisassemblerView::dispose() { RD_Free(m_disassembler); this->deleteLater(); }

ICommandTab* DisassemblerView::showListing()
{
    auto* listingtab = new ListingTab(m_disassembler);
    DisassemblerHooks::instance()->tab(listingtab, 0);
    return listingtab;
}
