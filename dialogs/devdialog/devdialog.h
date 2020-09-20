#pragma once

#include <QDialog>
#include "../hooks/idisassemblercommand.h"
#include "../hooks/idisposable.h"

namespace Ui {
class DevDialog;
}

class DevDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit DevDialog(QWidget *parent = nullptr);
        void setCommand(IDisassemblerCommand* command);
        ~DevDialog();

    private:
        Ui::DevDialog *ui;
        IDisassemblerCommand* m_command{nullptr};
};

