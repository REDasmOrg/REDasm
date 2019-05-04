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
        std::string currentWord() const;
        bool canGoBack() const;
        bool canGoForward() const;
        u64 visibleLines() const;
        u64 firstVisibleLine() const;
        u64 lastVisibleLine() const;
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

    public slots:
        void copy();

    private slots:
        void renderListing(const QRect& r = QRect());
        void renderLine(u64 line);

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
        void paintLines(QPainter* painter, u64 first, u64 last);
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);
        REDasm::ListingDocument& currentDocument();
        const REDasm::ListingDocument& currentDocument() const;
        const REDasm::Symbol *symbolUnderCursor();
        bool isLineVisible(u64 line) const;
        bool isColumnVisible(u64 column, u64 *xpos);
        QRect lineRect(u64 line);
        void paintLines(u64 first, u64 last);
        void blinkCursor();
        void adjustScrollBars();
        void moveToSelection();
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
