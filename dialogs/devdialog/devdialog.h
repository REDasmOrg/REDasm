#pragma once

#include <QDialog>
#include "../hooks/idisassemblercommand.h"
#include "../hooks/idisposable.h"

namespace Ui {
class DevDialog;
}

class DevDialog : public QDialog, public IDisposable
{
    Q_OBJECT

    public:
        explicit DevDialog(QWidget *parent = nullptr);
        void setCommand(IDisassemblerCommand* command);
        void dispose() override;
        ~DevDialog();

    private:
        Ui::DevDialog *ui;
        IDisassemblerCommand* m_command{nullptr};
};

