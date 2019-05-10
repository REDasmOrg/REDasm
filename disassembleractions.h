#ifndef DISASSEMBLERACTIONS_H
#define DISASSEMBLERACTIONS_H

#include <QAction>
#include <QObject>
#include <QMenu>
#include <redasm/disassembler/listing/listingrenderer.h>

class DisassemblerActions : public QObject
{
    Q_OBJECT

    public:
        enum { Rename = 0, XRefs, Follow, FollowPointerHexDump,
               CallGraph, Goto, HexDump, HexDumpFunction, Comment,
               Back, Forward, Copy };

    public:
        explicit DisassemblerActions(QWidget *parent = nullptr);
        explicit DisassemblerActions(REDasm::ListingRenderer *renderer, QWidget *parent = nullptr);
        void setCurrentRenderer(REDasm::ListingRenderer* renderer);
        REDasm::ListingRenderer* renderer() const;

    public slots:
        bool followUnderCursor();
        void setEnabled(bool b);
        void popup(const QPoint& pos);
        void copy();

    private slots:
        void adjustActions();
        void goTo(address_t address);
        void renameSymbolUnderCursor();
        void showReferencesUnderCursor();
        void printFunctionHexDump();
        void followPointerHexDump();
        void showCallGraph();
        void showHexDump();
        void addComment();
        void goForward();
        void goBack();

    private:
        QWidget* widget() const;
        void createActions();

    signals:
        void hexDumpRequested(address_t address, u64 len);
        void referencesRequested(address_t address);
        void callGraphRequested(address_t address);
        void gotoDialogRequested();
        void switchToHexDump();

    private:
        REDasm::ListingRenderer* m_renderer;
        QHash<int, QAction*> m_actions;
        QMenu* m_contextmenu;
};

#endif // DISASSEMBLERACTIONS_H
