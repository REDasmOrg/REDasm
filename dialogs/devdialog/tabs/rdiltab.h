#pragma once

#include <QWidget>
#include "../../../hooks/icommand.h"

namespace Ui {
class RDILTab;
}

class RDILTab : public QWidget
{
    Q_OBJECT

    public:
        explicit RDILTab(QWidget *parent = nullptr);
        void setCommand(ICommand* command);
        Q_INVOKABLE void updateInformation();
        ~RDILTab();

    private:
        Ui::RDILTab *ui;
        ICommand* m_command{nullptr};
        rd_ptr<RDRenderer> m_renderer;
        rd_ptr<RDGraph> m_graph;
};

