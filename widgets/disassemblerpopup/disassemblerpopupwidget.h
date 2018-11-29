#ifndef DISASSEMBLERPOPUPWIDGET_H
#define DISASSEMBLERPOPUPWIDGET_H

#include <QPlainTextEdit>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/disassemblerapi.h>
#include "../../renderer/listingpopuprenderer.h"

class DisassemblerPopupWidget : public QPlainTextEdit
{
    Q_OBJECT

    public:
        explicit DisassemblerPopupWidget(ListingPopupRenderer* popuprenderer, REDasm::DisassemblerAPI *disassembler, QWidget *parent = NULL);
        bool renderPopup(const std::string& word, int line);
        void moreRows();
        void lessRows();
        int rows() const;

    private:
        void renderPopup();
        int getIndexOfWord(const std::string& word) const;

    private:
        ListingPopupRenderer* m_popuprenderer;
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingDocument* m_document;
        int m_index, m_rows;
};

#endif // DISASSEMBLERPOPUPWIDGET_H
