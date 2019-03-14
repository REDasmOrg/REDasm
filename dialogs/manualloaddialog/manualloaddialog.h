#ifndef MANUALLOADDIALOG_H
#define MANUALLOADDIALOG_H

#include <QDialog>
#include <redasm/plugins/plugins.h>

namespace Ui {
class ManualLoadDialog;
}

class ManualLoadDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ManualLoadDialog(REDasm::LoaderPlugin* loader, QWidget *parent = 0);
        ~ManualLoadDialog();

    private:
        void initText();
        void loadBits();
        void loadAssemblers();
        void updateInputMask();

    private slots:
        void on_buttonBox_accepted();

    private:
        Ui::ManualLoadDialog* ui;
        REDasm::LoaderPlugin* m_loader;
};

#endif // MANUALLOADDIALOG_H
