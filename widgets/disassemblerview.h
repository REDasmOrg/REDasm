#pragma once

#include <QObject>
#include <rdapi/rdapi.h>
#include "../hooks/idisposable.h"

struct RDDisassembler;
class ListingMapDock;
class ListingTab;

class DisassemblerView : public QObject, public IDisposable
{
    Q_OBJECT

    public:
        explicit DisassemblerView(RDDisassembler* disassembler, QObject *parent = nullptr);
        virtual ~DisassemblerView();
        RDDisassembler* disassembler() const;
        void dispose() override;

    private:
        RDDisassembler* m_disassembler;
        ListingMapDock* m_listingmapdock;
        ListingTab* m_listingtab;
};

