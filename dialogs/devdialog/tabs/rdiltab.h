#pragma once

#include <QWidget>
#include "../../../hooks/isurface.h"

namespace Ui {
class RDILTab;
}

class RDILTab : public QWidget
{
    Q_OBJECT

    public:
        explicit RDILTab(QWidget *parent = nullptr);
        void setContext(const RDContextPtr& ctx);
        Q_INVOKABLE void updateInformation();
        ~RDILTab();

    private:
        Ui::RDILTab *ui;
        RDContextPtr m_context;
        rd_ptr<RDGraph> m_graph;
};

