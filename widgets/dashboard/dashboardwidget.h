#pragma once

#include <QWidget>

class QPushButton;
class QLabel;

class DashboardWidget : public QWidget
{
    Q_OBJECT

    public:
        explicit DashboardWidget(QWidget *parent = nullptr);

    protected:
        void makeBordered(QPushButton* pb) const;
        void applyLogo(QLabel* lbl) const;
};

