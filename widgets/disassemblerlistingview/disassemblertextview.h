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
        bool canGoBack() const;
        bool canGoForward() const;
        u64 visibleLines() const;
        u64 firstVisibleLine() const;
        u64 lastVisibleLine() const;
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public slots:
        void copy();
        void goTo(REDasm::ListingItem *item);
        void goTo(address_t address);
        void goBack();
        void goForward();

    private slots:
        void blinkCursor();
        void showReferencesUnderCursor();
        void renameCurrentSymbol();
        bool followUnderCursor();
        void addComment();
        void printFunctionHexDump();
        void showCallGraph();
        void showHexDump();

    protected:
        virtual void scrollContentsBy(int dx, int dy);
        virtual void focusInEvent(QFocusEvent* e);
        virtual void focusOutEvent(QFocusEvent* e);
        virtual void paintEvent(QPaintEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseDoubleClickEvent(QMouseEvent* e);
        virtual void wheelEvent(QWheelEvent *e);
        virtual void keyPressEvent(QKeyEvent *e);
        virtual bool event(QEvent* e);

    private:
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);

    private:
        REDasm::SymbolPtr symbolUnderCursor();
        bool isLineVisible(u64 line) const;
        bool isColumnVisible(u64 column, u64 *xpos);
        void adjustScrollBars();
        void moveToSelection();
        void createContextMenu();
        void adjustContextMenu();
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

    private:
        std::unique_ptr<ListingTextRenderer> m_renderer;
        REDasm::DisassemblerAPI* m_disassembler;
        DisassemblerPopup* m_disassemblerpopup;
        QAction *m_actrename, *m_actxrefs, *m_actfollow, *m_actcallgraph;
        QAction *m_actgoto, *m_acthexdumpshow, *m_acthexdumpfunc;
        QAction *m_actcomment, *m_actback, *m_actforward, *m_actcopy;
        QMenu* m_contextmenu;
        QTimer* m_blinktimer;
};

#endif // DISASSEMBLERTEXTVIEW_H
