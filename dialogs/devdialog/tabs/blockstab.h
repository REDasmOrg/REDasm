#pragma once

#include <QWidget>
#include "../../../models/segmentsmodel.h"
#include "../../../hooks/isurface.h"

namespace Ui {
class BlocksTab;
}

class BlocksTab : public QWidget
{
    Q_OBJECT

    public:
        explicit BlocksTab(QWidget *parent = nullptr);
        ~BlocksTab();
        void setContext(const RDContextPtr& ctx);

    private Q_SLOTS:
        void showBlocks(const QModelIndex& current, const QModelIndex&);

    private:
        Ui::BlocksTab *ui;
        SegmentsModel* m_segmentsmodel{nullptr};
        RDContextPtr m_context;
};

