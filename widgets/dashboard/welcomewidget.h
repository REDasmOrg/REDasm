#pragma once

#include "dashboardwidget.h"

namespace Ui {
class WelcomeWidget;
}

class WelcomeWidget : public DashboardWidget
{
    Q_OBJECT

    public:
        explicit WelcomeWidget(QWidget *parent = nullptr);
        ~WelcomeWidget();

    private:
        void styleSocialButton(QPushButton* button, const QIcon& icon) const;

    private Q_SLOTS:
        void onFileSelected(const QModelIndex& index);

    private:
        Ui::WelcomeWidget *ui;
};
