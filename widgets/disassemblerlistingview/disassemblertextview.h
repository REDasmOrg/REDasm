#ifndef DISASSEMBLERTEXTVIEW_H
#define DISASSEMBLERTEXTVIEW_H

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QMenu>
#include "../../renderer/listingtextrenderer.h"
#include "../disassemblerpopup/disassemblerpopup.h"

class DisassemblerTextView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = 0);
        virtual ~DisassemblerTextView();
        bool canGoBack() const;
        bool canGoForward() const;
        u64 visibleLines() const;
        u64 firstVisibleLine() const;
        u64 lastVisibleLine() const;
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public slots:
        void copy();
        void goTo(REDasm::ListingItem *item);
        bool goTo(address_t address);

    private slots:
        void goBack();
        void goForward();
        void renderListing(const QRect& r = QRect());
        void renderLine(u64 line);
        void showReferencesUnderCursor();
        void renameCurrentSymbol();
        bool followUnderCursor();
        bool followPointerHexDump();
        void addComment();
        void printFunctionHexDump();
        void showCallGraph();
        void showHexDump();

    protected:
        virtual void scrollContentsBy(int dx, int dy);
        virtual void paintEvent(QPaintEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseDoubleClickEvent(QMouseEvent* e);
        virtual void wheelEvent(QWheelEvent *e);
        virtual void keyPressEvent(QKeyEvent *e);
        virtual void timerEvent(QTimerEvent* e);
        virtual bool event(QEvent* e);

    protected:
        virtual void paintLines(QPainter* painter, u64 first, u64 last);

    private:
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);

    private:
        const REDasm::Symbol *symbolUnderCursor();
        bool isLineVisible(u64 line) const;
        bool isColumnVisible(u64 column, u64 *xpos);
        QRect lineRect(u64 line);
        void paintLines(u64 first, u64 last);
        void blinkCursor();
        void adjustScrollBars();
        void moveToSelection();
        void createContextMenu();
        void adjustContextMenu();
        void ensureColumnVisible();
        void showPopup(const QPoint &pos);

    signals:
        void switchView();
        void switchToHexDump();
        void gotoRequested();
        void canGoBackChanged();
        void canGoForwardChanged();
        void callGraphRequested(address_t address);
        void hexDumpRequested(address_t address, u64 len);
        void addressChanged(address_t address);
        void referencesRequested(address_t address);

    protected:
        std::unique_ptr<ListingTextRenderer> m_renderer;

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        DisassemblerPopup* m_disassemblerpopup;
        QAction *m_actrename, *m_actxrefs, *m_actfollow, *m_actfollowpointer, *m_actcallgraph;
        QAction *m_actgoto, *m_acthexdumpshow, *m_acthexdumpfunc;
        QAction *m_actcomment, *m_actback, *m_actforward, *m_actcopy;
        QMenu* m_contextmenu;
        int m_refreshrate, m_blinktimerid, m_refreshtimerid;
};

#endif // DISASSEMBLERTEXTVIEW_H
