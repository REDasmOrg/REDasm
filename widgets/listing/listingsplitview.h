#pragma once

#include <QSplitter>
#include "../hooks/icommand.h"
#include "../splitview/splitview.h"

class ListingSplitView : public SplitView
{
    Q_OBJECT

    public:
        explicit ListingSplitView(const RDContextPtr& ctx, QWidget *parent = nullptr);

    protected:
        QWidget* createWidget() override;
        void onItemSplit(const SplitItem* item, const SplitItem* newitem) const override;
        void onItemCreated(SplitItem* item) const override;

    private:
        RDContextPtr m_context;
};

