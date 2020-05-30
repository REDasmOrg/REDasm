#pragma once

#include <QObject>
#include <rdapi/rdapi.h>
#include "../hooks/idisposable.h"
#include "../hooks/icommandtab.h"

struct RDDisassembler;
class ListingMapDock;

class DisassemblerView : public QObject, public IDisposable
{
    Q_OBJECT

    public:
        explicit DisassemblerView(RDDisassembler* disassembler, QObject *parent = nullptr);
        RDDisassembler* disassembler() const;
        void dispose() override;

    public:
        ICommandTab* showListing();

    private:
        RDDisassembler* m_disassembler;
        ListingMapDock* m_listingmapdock;
};

