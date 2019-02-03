#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QComboBox>

namespace Ui {
class SettingsDialog;
}

class SettingsDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit SettingsDialog(QWidget *parent = nullptr);
        ~SettingsDialog();

    private:
        void selectCurrentTheme();

    private slots:
        void onAccepted();

    private:
        Ui::SettingsDialog *ui;
};

#endif // SETTINGSDIALOG_H
