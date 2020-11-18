#pragma once

#include <QSplitter>
#include "../hooks/icommand.h"
#include "../splitview/splitview.h"

class ListingSplitView : public SplitView
{
    Q_OBJECT

    public:
        Q_INVOKABLE explicit ListingSplitView(const RDContextPtr& ctx, QWidget *parent = nullptr);

    protected:
        SplitView* createView() const override;
        QWidget* createWidget() override;
        void onItemSplit(SplitItem* item, SplitItem* newitem) override;
        void onItemCreated(SplitItem* item) override;

    private:
        void checkActions(SplitItem* item) const;

    private:
        RDContextPtr m_context;
};

