#pragma once

#include <QWidget>
#include "../../../models/segmentsmodel.h"
#include "../../../hooks/idisassemblercommand.h"

namespace Ui {
class BlocksTab;
}

class BlocksTab : public QWidget
{
    Q_OBJECT

    public:
        explicit BlocksTab(QWidget *parent = nullptr);
        ~BlocksTab();
        void setCommand(ICommand* command);

    private slots:
        void showBlocks(const QModelIndex& current, const QModelIndex&);

    private:
        Ui::BlocksTab *ui;
        SegmentsModel* m_segmentsmodel{nullptr};
        ICommand* m_command{nullptr};
};

