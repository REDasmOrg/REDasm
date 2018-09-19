#ifndef DISASSEMBLERTEXTVIEW_H
#define DISASSEMBLERTEXTVIEW_H

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QMenu>
#include "listingtextrenderer.h"

class DisassemblerTextView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = 0);
        ~DisassemblerTextView();
        bool canGoBack() const;
        bool canGoForward() const;
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public slots:
        void copy();
        void goTo(REDasm::ListingItem *item);
        void goTo(address_t address);
        void goBack();
        void goForward();

    private slots:
        void blinkCursor();

    protected:
        virtual bool viewportEvent(QEvent* e);
        virtual void paintEvent(QPaintEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseDoubleClickEvent(QMouseEvent* e);
        virtual void keyPressEvent(QKeyEvent *e);

    private:
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);

    private:
        REDasm::SymbolPtr symbolUnderCursor();
        int visibleLines() const;
        int firstVisibleLine() const;
        int lastVisibleLine() const;
        bool isLineVisible(int line) const;
        void adjustScrollBars();
        void moveToSelection();
        void createContextMenu();
        void adjustContextMenu();
        void showReferences();
        void showCallGraph(address_t address);
        bool followUnderCursor();
        void renameCurrentSymbol();

    signals:
        void gotoRequested();
        void canGoBackChanged();
        void canGoForwardChanged();
        void hexDumpRequested(address_t address);
        void addressChanged(address_t address);

    private:
        ListingTextRenderer* m_renderer;
        REDasm::DisassemblerAPI* m_disassembler;
        QAction *m_actrename, *m_actxrefs, *m_actfollow, *m_actcallgraph;
        QAction *m_actgoto, *m_acthexdump, *m_actback, *m_actforward, *m_actcopy;
        QMenu* m_contextmenu;
        QTimer* m_blinktimer;
};

#endif // DISASSEMBLERTEXTVIEW_H
