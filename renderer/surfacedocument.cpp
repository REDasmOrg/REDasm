#include "surfacedocument.h"
#include <QTextDocument>
#include <QTextCursor>
#include <QPainter>
#include <QWidget>

SurfaceDocument::SurfaceDocument(const RDContextPtr& ctx, rd_flag flags, QObject *parent) : SurfaceQt(ctx, flags, parent)
{
    m_document = new QTextDocument(this);
    m_document->setDefaultFont(this->widget()->font());
    m_document->setUndoRedoEnabled(false);
    m_document->setDocumentMargin(0);
}

void SurfaceDocument::renderTo(QPainter* painter) { m_document->drawContents(painter); }

void SurfaceDocument::render()
{
    m_document->clear();

    int rows = 0;
    RDSurface_GetSize(this->handle(), &rows, nullptr);

    QTextCursor textcursor(m_document);
    const RDSurfaceCell* cells = nullptr;
    QTextCharFormat cf;

    for(int row = 0; row < rows; row++)
    {
        int maxcols = RDSurface_GetRow(this->handle(), row, &cells);
        if(row) textcursor.insertBlock();

        for(int col = 0; col < maxcols; col++)
        {
            auto& cell = cells[col];
            cf.setBackground(this->getBackground(&cell));
            cf.setForeground(this->getForeground(&cell));
            textcursor.insertText(QString(cell.ch), cf);
        }
    }

    Q_EMIT renderCompleted();
}
