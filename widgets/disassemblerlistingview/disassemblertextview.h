#ifndef DISASSEMBLERTEXTVIEW_H
#define DISASSEMBLERTEXTVIEW_H

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QMenu>
#include "../../renderer/listingtextrenderer.h"
#include "../disassemblerpopup/disassemblerpopup.h"
#include "../disassembleractions.h"

class DisassemblerTextView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = nullptr);
        virtual ~DisassemblerTextView();
        DisassemblerActions* disassemblerActions() const;
        REDasm::String currentWord() const;
        bool canGoBack() const;
        bool canGoForward() const;
        size_t visibleLines() const;
        size_t firstVisibleLine() const;
        size_t lastVisibleLine() const;
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

    public slots:
        void copy();

    private slots:
        void renderListing(const QRect& r = QRect());
        void renderLine(size_t line);
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
        void paintLines(QPainter* painter, size_t first, size_t last);
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);
        REDasm::ListingDocument& currentDocument();
        const REDasm::ListingDocument& currentDocument() const;
        const REDasm::Symbol *symbolUnderCursor();
        bool isLineVisible(size_t line) const;
        bool isColumnVisible(size_t column, size_t *xpos);
        QRect lineRect(size_t line);
        void paintLines(size_t first, size_t last);
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
        std::unique_ptr<ListingTextRenderer> m_renderer;
        REDasm::DisassemblerPtr m_disassembler;
        DisassemblerPopup* m_disassemblerpopup;
        DisassemblerActions* m_actions;
        int m_refreshrate, m_blinktimerid, m_refreshtimerid;
};

#endif // DISASSEMBLERTEXTVIEW_H
