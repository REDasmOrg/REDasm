#pragma once

#include <QObject>
#include <rdapi/rdapi.h>

struct RDDisassembler;
class ListingMapDock;
class ListingTab;

class DisassemblerView : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerView(RDDisassembler* disassembler, QObject *parent = nullptr);
        RDDisassembler* disassembler() const;
        ~DisassemblerView();

    private:
        RDDisassembler* m_disassembler;
        ListingMapDock* m_listingmapdock;
        ListingTab* m_listingtab;
        event_t m_cursorevent;
};

