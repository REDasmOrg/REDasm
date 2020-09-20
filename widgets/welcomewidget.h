#pragma once

#include <QWidget>

namespace Ui {
class WelcomeWidget;
}

class QPushButton;

class WelcomeWidget : public QWidget
{
    Q_OBJECT

    public:
        explicit WelcomeWidget(QWidget *parent = nullptr);
        ~WelcomeWidget();

    private:
        void styleSocialButton(QPushButton* button, const QIcon& icon) const;

    private slots:
        void onFileSelected(const QModelIndex& index);

    private:
        Ui::WelcomeWidget *ui;
};
