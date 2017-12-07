#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QDialog>
#include <list>

namespace Ui {
class AboutDialog;
}

class AboutDialog : public QDialog
{
    Q_OBJECT

    private:
        struct DependsInfo { QString name, version, url; };

    public:
        explicit AboutDialog(QWidget *parent = 0);
        ~AboutDialog();

    private:
        void initItems();
        void initDepends();

    private:
        Ui::AboutDialog *ui;
        std::list<DependsInfo> _depends;

};

#endif // ABOUTDIALOG_H
