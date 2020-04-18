#pragma once

#include <QObject>
#include <QAction>
#include <QMenu>
#include <redasm/disassembler/listing/listingrenderer.h>
#include "renderer/painterrenderer.h"

class DisassemblerActions : public QObject
{
    Q_OBJECT

    public:
        enum { Action_Rename = 0, Action_XRefs, Action_Follow, Action_FollowPointerHexDump,
               Action_CallGraph, Action_Goto, Action_HexDump, Action_HexDumpFunction, Action_Comment, Action_CreateFunction,
               Action_Back, Action_Forward, Action_Copy,
               Action_ItemInformation };

    public:
        explicit DisassemblerActions(QWidget *parent = nullptr);
        explicit DisassemblerActions(PainterRenderer *renderer, QWidget *parent = nullptr);
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
        void createFunction();
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
        void itemInformationRequested();
        void gotoDialogRequested();
        void switchToHexDump();

    private:
        QHash<int, QAction*> m_actions;
        PainterRenderer* m_renderer{nullptr};
        QMenu* m_contextmenu{nullptr};
};
