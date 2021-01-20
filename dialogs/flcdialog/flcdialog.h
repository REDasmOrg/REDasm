#pragma once

#include <QDialog>
#include "../hooks/isurface.h"

namespace Ui {
class FLCDialog;
}

class FLCDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit FLCDialog(QWidget *parent = nullptr);
        ~FLCDialog();
        void showFLC(const RDContextPtr& ctx);

    protected:
        void closeEvent(QCloseEvent* e);

    private:
        Ui::FLCDialog *ui;
        RDContextPtr m_context;
};

