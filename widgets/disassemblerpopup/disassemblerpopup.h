#pragma once

#include <QWidget>
#include <memory>
#include <rdapi/rdapi.h>
#include "../../renderer/documentrenderer.h"
#include "disassemblerpopupwidget.h"

class DisassemblerPopup : public QWidget
{
    public:
        explicit DisassemblerPopup(const RDDisassemblerPtr& disassembler, QWidget* parent = nullptr);
        void popup(const QString& word, size_t line);

    protected:
        void mouseMoveEvent(QMouseEvent *e) override;
        void wheelEvent(QWheelEvent* e) override;

    private:
        void updateGeometry();

    private:
        RDDisassemblerPtr m_disassembler;
        QTextDocument* m_textdocument;
        DisassemblerPopupWidget* m_popupwidget;
        std::unique_ptr<DocumentRenderer> m_renderer;
        QPoint m_lastpos;
};
