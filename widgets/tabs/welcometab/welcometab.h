#pragma once

#include <QWidget>

namespace Ui {
class WelcomeTab;
}

class QPushButton;

class WelcomeTab : public QWidget
{
    Q_OBJECT

    public:
        explicit WelcomeTab(QWidget *parent = nullptr);
        ~WelcomeTab();

    private:
        void styleSocialButton(QPushButton* button, const QIcon& icon) const;

    private slots:
        void onFileSelected(const QModelIndex& index);

    private:
        Ui::WelcomeTab *ui;
};
