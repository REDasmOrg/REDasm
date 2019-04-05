#ifndef DISASSEMBLERPOPUP_H
#define DISASSEMBLERPOPUP_H

#include <QWidget>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/disassemblerapi.h>
#include "../../renderer/listingpopuprenderer.h"
#include "disassemblerpopupwidget.h"

class DisassemblerPopup : public QWidget
{
    public:
        explicit DisassemblerPopup(const REDasm::DisassemblerPtr& disassembler, QWidget* parent = nullptr);
        ~DisassemblerPopup();
        void popup(const std::string& word, int line);

    protected:
        virtual void mouseMoveEvent(QMouseEvent *e);
        virtual void wheelEvent(QWheelEvent* e);

    private:
        void updateGeometry();

    private:
        DisassemblerPopupWidget* m_popupwidget;
        ListingPopupRenderer* m_popuprenderer;

    private:
        QPoint m_lastpos;
};

#endif // DISASSEMBLERPOPUP_H
