#pragma once

#include <QTabWidget>
#include "../hooks/idisassemblercommand.h"

class DisassemblerTabs : public QTabWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabs(const RDContextPtr& ctx, QWidget *parent = nullptr);
        int tabHeight() const;

    protected:
        void tabInserted(int index) override;

    private slots:
        void onTabChanged(int index);
        void onCloseClicked();

    private:
        RDContextPtr m_context;
};
