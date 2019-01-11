#ifndef DISASSEMBLERWEBCHANNEL_H
#define DISASSEMBLERWEBCHANNEL_H

#include <QObject>
#include <redasm/disassembler/disassemblerapi.h>
#include <redasm/disassembler/listing/listingdocument.h>

class DisassemblerWebChannel : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerWebChannel(REDasm::DisassemblerAPI* disassembler, QObject *parent = nullptr);

    public slots:
        void followUnderCursor();
        void showReferencesUnderCursor();
        void switchToListing();
        void moveTo(int line, const QString& word = QString());

    signals:
        void addressChanged(address_t address);
        void referencesRequested(address_t address);
        void switchView();

    private:
        REDasm::ListingDocument& m_document;
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingCursor* m_cursor;
};

#endif // DISASSEMBLERWEBCHANNEL_H
