#ifndef DISASSEMBLERWEBCHANNEL_H
#define DISASSEMBLERWEBCHANNEL_H

#include <QObject>
#include "../../redasm/disassembler/disassemblerapi.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

class DisassemblerWebChannel : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerWebChannel(REDasm::DisassemblerAPI* disassembler, QObject *parent = nullptr);

    public slots:
        void switchToListing();
        void moveTo(int line, const QString& word);

    signals:
        void addressChanged(address_t address);
        void switchView();

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingDocument* m_document;
        REDasm::ListingCursor* m_cursor;
};

#endif // DISASSEMBLERWEBCHANNEL_H
