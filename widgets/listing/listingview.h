#pragma once

#include <QStackedWidget>
#include <rdapi/rdapi.h>
#include "listinggraphview/listinggraphview.h"
#include "listingtextview/listingtextview.h"
#include "../../hooks/icommand.h"

class ListingView : public QStackedWidget
{
    Q_OBJECT

    public:
        explicit ListingView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool getCurrentItem(RDDocumentItem* item);

    public slots:
        void switchToGraph();
        void switchToListing();
        void switchMode();

    protected:
        bool eventFilter(QObject *object, QEvent *event) override;

    private:
        RDContextPtr m_context;
        ListingTextView* m_textview;
        ListingGraphView* m_graphview;
};
