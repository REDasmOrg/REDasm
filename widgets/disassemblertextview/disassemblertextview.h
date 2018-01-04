#ifndef DISASSEMBLERTEXTVIEW_H
#define DISASSEMBLERTEXTVIEW_H

#include <QPlainTextEdit>
#include <QStack>
#include "disassemblertextdocument.h"
#include "disassemblerhighlighter.h"

class DisassemblerTextView : public QPlainTextEdit
{
    Q_OBJECT

    public:
        enum EmitMode { Normal, VMIL };

    public:
        explicit DisassemblerTextView(QWidget *parent = 0);
        ~DisassemblerTextView();
        bool canGoBack() const;
        bool canGoForward() const;
        address_t currentAddress() const;
        address_t symbolAddress() const;
        void setEmitMode(u32 emitmode);
        void setDisassembler(REDasm::Disassembler* disassembler);

    public slots:
        void goTo(const REDasm::SymbolPtr& symbol);
        void goTo(address_t address);
        void rename(address_t address);
        void goBack();
        void goForward();

    protected:
        virtual void resizeEvent(QResizeEvent *e);
        virtual void wheelEvent(QWheelEvent *e);
        virtual void mouseReleaseEvent(QMouseEvent *e);
        virtual void mouseDoubleClickEvent(QMouseEvent *e);
        virtual void keyPressEvent(QKeyEvent *e);

    private:
        void createContextMenu();
        void adjustContextMenu();
        void highlightWords();
        void updateAddress();
        void updateSymbolAddress(address_t address);
        void display(address_t address);
        void showReferences(address_t address);
        int getCursorAnchor(address_t &address);

    signals:
        void gotoRequested();
        void canGoBackChanged();
        void canGoForwardChanged();
        void invalidateSymbols();
        void hexDumpRequested(address_t address);
        void symbolRenamed(const REDasm::SymbolPtr& symbol);
        void symbolAddressChanged();
        void symbolDeselected();
        void addressChanged(address_t address);

    private:
        u32 _emitmode;
        QStack<address_t> _backstack, _forwardstack;
        DisassemblerTextDocument* _disdocument;
        DisassemblerHighlighter* _highlighter;
        REDasm::Disassembler* _disassembler;
        QAction *_actrename, *_actcreatestring, *_actxrefs, *_actfollow, *_actgoto, *_acthexdump, *_actback, *_actforward, *_actcopy, *_actselectall;
        QMenu* _contextmenu;
        address_t _currentaddress, _symboladdress;
};

#endif // DISASSEMBLERTEXTVIEW_H
