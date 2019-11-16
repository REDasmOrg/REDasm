#pragma once

#include <QWidget>
#include <redasm/disassembler/disassembler.h>
#include "../../renderer/listingdocumentrenderer.h"
#include "disassemblerpopupwidget.h"

class DisassemblerPopup : public QWidget
{
    public:
        explicit DisassemblerPopup(const REDasm::DisassemblerPtr& disassembler, QWidget* parent = nullptr);
        ~DisassemblerPopup();
        void popup(const REDasm::String &word, size_t line);

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
