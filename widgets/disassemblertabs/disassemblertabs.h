#pragma once

#include <QTabWidget>
#include "../hooks/isurface.h"

class DisassemblerTabs : public QTabWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabs(const RDContextPtr& ctx, QWidget *parent = nullptr);
        int tabHeight() const;

    protected:
        void tabInserted(int index) override;

    private Q_SLOTS:
        void onTabChanged(int index);
        void onCloseClicked();

    private:
        RDContextPtr m_context;
};
