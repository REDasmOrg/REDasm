#pragma once

#include <QStackedWidget>
#include <future>
#include <qhexview/qhexview.h>
#include <rdapi/rdapi.h>
#include "listinggraphview/listinggraphview.h"
#include "listingtextview/listingtextview.h"
#include "../../hooks/isurface.h"

class ListingView : public QStackedWidget
{
    Q_OBJECT

    private:
        enum { Action_Rename = 0, Action_XRefs, Action_Follow, Action_FollowPointerHexDump,
               Action_CallGraph, Action_Goto, Action_HexDump, Action_HexDumpFunction, Action_Comment, Action_CreateFunction, Action_SwitchView,
               Action_Back, Action_Forward, Action_Copy };

    public:
        explicit ListingView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool getCurrentItem(RDDocumentItem* item);
        ISurface* currentISurface() const;

    public slots:
        void switchToGraph();
        void switchToListing();
        void switchToHex();
        void switchMode();
        void showGoto();

    protected:
        bool eventFilter(QObject *object, QEvent *event) override;

    private slots:
        void adjustActions();

    private:
        QMenu* createActions(ISurface* surface);
        void showReferences(rd_address address);
        void prepareHexDocument();

    signals:
        void historyChanged();

    private:
        std::future<void> m_worker;
        RDContextPtr m_context;
        ListingTextView* m_textview;
        ListingGraphView* m_graphview;
        QHexView* m_hexview;
};
