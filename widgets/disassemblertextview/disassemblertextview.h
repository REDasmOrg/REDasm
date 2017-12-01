#ifndef DISASSEMBLERTEXTVIEW_H
#define DISASSEMBLERTEXTVIEW_H

#include <QTextBrowser>
#include <QStack>
#include "disassemblerdocument.h"

class DisassemblerTextView : public QTextBrowser
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = 0);
        ~DisassemblerTextView();
        bool canGoBack() const;
        bool canGoForward() const;
        address_t currentAddress() const;
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void goTo(const REDasm::SymbolPtr& symbol);
        void goTo(address_t address);
        void rename(address_t address);
        void goBack();
        void goForward();

    protected:
        virtual void mouseReleaseEvent(QMouseEvent *ev);

    private slots:
        void executeAnchor(const QString &encdata);

    private:
        int lineFromPos(const QPoint& pos) const;
        int firstVisibleLine() const;
        int lastVisibleLine() const;
        int visibleLines() const;
        void centerSelection();
        void createContextMenu();
        void adjustContextMenu();
        void display(address_t address);
        void highlightLineAt(const QPoint& pos);
        void highlightLine(int line);
        void focusLine(int line);
        void focusLineAt(address_t address);
        void showReferences(address_t address);
        void disassemble();
        void updateListing();

    signals:
        void gotoRequested();
        void canGoBackChanged();
        void canGoForwardChanged();
        void invalidateSymbols();
        void hexDumpRequested(address_t address);
        void symbolRenamed(const REDasm::SymbolPtr& symbol);
        void addressChanged(address_t address);

    private:
        QStack<address_t> _backstack, _forwardstack;
        DisassemblerDocument* _disdocument;
        REDasm::Disassembler* _disassembler;
        QAction *_actrename, *_actcreatefunction, *_actcreatestring, *_actxrefs, *_actfollow, *_actgoto, *_acthexdump, *_actback, *_actforward, *_actcopy, *_actselectall;
        QMenu* _contextmenu;
        address_t _currentaddress, _menuaddress;
};

#endif // DISASSEMBLERTEXTVIEW_H
