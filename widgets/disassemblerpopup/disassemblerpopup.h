#ifndef DISASSEMBLERPOPUP_H
#define DISASSEMBLERPOPUP_H

#include <QWidget>
#include <core/disassembler/listing/listingdocument.h>
#include <core/disassembler/disassemblerapi.h>
#include "../../renderer/listingdocumentrenderer.h"
#include "disassemblerpopupwidget.h"

class DisassemblerPopup : public QWidget
{
    public:
        explicit DisassemblerPopup(const REDasm::DisassemblerPtr& disassembler, QWidget* parent = nullptr);
        ~DisassemblerPopup();
        void popup(const std::string& word, int line);

    protected:
        void mouseMoveEvent(QMouseEvent *e) override;
        void wheelEvent(QWheelEvent* e) override;

    private:
        void updateGeometry();

    private:
        DisassemblerPopupWidget* m_popupwidget;
        ListingDocumentRenderer* m_documentrenderer;

    private:
        QPoint m_lastpos;
};

#endif // DISASSEMBLERPOPUP_H
