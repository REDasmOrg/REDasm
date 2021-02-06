#pragma once

#include "../docks/splitdockwidget.h"
#include "../hooks/isurface.h"

class ListingSplitView : public SplitDockWidget
{
    Q_OBJECT

    public:
        Q_INVOKABLE explicit ListingSplitView(const RDContextPtr& ctx);

    protected:
        SplitDockWidget* createSplit() const override;

    private Q_SLOTS:
        void checkActions() const;

    private:
        RDContextPtr m_context;
};

