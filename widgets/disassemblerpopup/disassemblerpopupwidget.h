#pragma once

#include <QPlainTextEdit>
#include <rdapi/disassembler.h>
#include "../../renderer/documentrenderer.h"

class DisassemblerPopupWidget : public QPlainTextEdit
{
    Q_OBJECT

    public:
        explicit DisassemblerPopupWidget(DocumentRenderer* renderer, const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool renderPopup(const QString& word, size_t line);
        void moreRows();
        void lessRows();
        int rows() const;

    private:
        void renderPopup();
        size_t getIndexOfWord(const QString& word) const;

    private:
        RDContextPtr m_context;
        RDDocument* m_document;
        DocumentRenderer* m_renderer;
        size_t m_index{RD_NPOS}, m_rows;
};
