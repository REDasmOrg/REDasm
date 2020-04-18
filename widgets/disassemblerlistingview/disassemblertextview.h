#pragma once

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QMenu>
#include <rdapi/rdapi.h>
#include "../../renderer/painterrenderer.h"
#include "../disassemblerpopup/disassemblerpopup.h"
#include "../actions/disassembleractions.h"

class DisassemblerTextView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = nullptr);
        virtual ~DisassemblerTextView();
        DisassemblerActions* disassemblerActions() const;
        RDDisassembler* disassembler() const;
        RDCursor* activeCursor() const;
        bool getCurrentItem(RDDocumentItem* item) const;
        QString currentWord() const;
        bool canGoBack() const;
        bool canGoForward() const;
        size_t visibleLines() const;
        size_t firstVisibleLine() const;
        size_t lastVisibleLine() const;
        void setDisassembler(RDDisassembler* disassembler);

    public slots:
        void copy();

    private slots:
        void moveToSelection();

    protected:
        void scrollContentsBy(int dx, int dy) override;
        void paintEvent(QPaintEvent* e) override;
        void resizeEvent(QResizeEvent* e) override;
        void mousePressEvent(QMouseEvent* e) override;
        void mouseMoveEvent(QMouseEvent* e) override;
        void mouseReleaseEvent(QMouseEvent* e) override;
        void mouseDoubleClickEvent(QMouseEvent* e) override;
        void wheelEvent(QWheelEvent *e) override;
        void keyPressEvent(QKeyEvent *e) override;
        void timerEvent(QTimerEvent* e) override;
        bool event(QEvent* e) override;

    private:
        const REDasm::Symbol *symbolUnderCursor();
        QRect lineRect(size_t line) const;
        QPointF viewportPoint(const QPointF& pt) const;
        void paintLine(size_t line);
        void paintLines(size_t first, size_t last);
        void onDocumentChanged(const RDEventArgs* e);
        bool isLineVisible(size_t line) const;
        bool isColumnVisible(size_t column, size_t* xpos);
        void blinkCursor();
        void adjustScrollBars();
        void ensureColumnVisible();
        void showPopup(const QPoint &pos);

    signals:
        void switchView();
        void canGoBackChanged();
        void canGoForwardChanged();
        void addressChanged(address_t address);

    private:
        QSet<event_t> m_events;
        std::unique_ptr<PainterRenderer> m_renderer;
        RDDisassembler* m_disassembler{nullptr};
        RDDocument* m_document{nullptr};

    private:
        DisassemblerPopup* m_disassemblerpopup{nullptr};
        DisassemblerActions* m_actions{nullptr};
        int m_blinktimer{0};
};
