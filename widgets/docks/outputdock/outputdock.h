#pragma once

#include <QDockWidget>

namespace Ui {
class OutputDock;
}

class OutputDock : public QDockWidget
{
    Q_OBJECT

    public:
        explicit OutputDock(QWidget *parent = nullptr);
        ~OutputDock();
        void log(const QString& s);
        void clear();

    private:
        Ui::OutputDock *ui;
};

