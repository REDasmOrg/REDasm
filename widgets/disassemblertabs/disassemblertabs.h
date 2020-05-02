#pragma once

#include <QTabWidget>

class DisassemblerTabs : public QTabWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabs(QWidget *parent = nullptr);
        int tabHeight() const;

    protected:
        void tabInserted(int index) override;

    private slots:
        void onTabChanged(int index);
        void onCloseClicked();
};
