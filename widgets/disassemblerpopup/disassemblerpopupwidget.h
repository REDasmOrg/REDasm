#ifndef DISASSEMBLERPOPUPWIDGET_H
#define DISASSEMBLERPOPUPWIDGET_H

#include <QPlainTextEdit>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/disassembler.h>
#include "../../renderer/listingdocumentrenderer.h"

class DisassemblerPopupWidget : public QPlainTextEdit
{
    Q_OBJECT

    public:
        explicit DisassemblerPopupWidget(ListingDocumentRenderer* documentrenderer, const REDasm::DisassemblerPtr& disassembler, QWidget *parent = nullptr);
        bool renderPopup(const REDasm::String& word, int line);
        void moreRows();
        void lessRows();
        int rows() const;

    private:
        void renderPopup();
        size_t getIndexOfWord(const REDasm::String &word) const;

    private:
        REDasm::DisassemblerPtr m_disassembler;
        REDasm::ListingDocument& m_document;
        ListingDocumentRenderer* m_documentrenderer;
        size_t m_index, m_rows;
};

#endif // DISASSEMBLERPOPUPWIDGET_H
