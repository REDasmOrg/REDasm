#pragma once

#include <QDialog>
#include "../hooks/isurface.h"

namespace Ui {
class DevDialog;
}

class DevDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit DevDialog(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~DevDialog();

    protected:
        void showEvent(QShowEvent* e) override;

    private:
        void updateInformation();

    private:
        Ui::DevDialog *ui;
        RDContextPtr m_context;
};

