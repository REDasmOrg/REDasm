#ifndef MANUALLOADDIALOG_H
#define MANUALLOADDIALOG_H

#include <QDialog>
#include "../redasm/plugins/plugins.h"

namespace Ui {
class ManualLoadDialog;
}

class ManualLoadDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ManualLoadDialog(REDasm::FormatPlugin* format, u64 size, QWidget *parent = 0);
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
        REDasm::FormatPlugin* m_format;
        u64 m_size;
};

#endif // MANUALLOADDIALOG_H
