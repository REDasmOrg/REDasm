#include "dashboardwidget.h"
#include "../../themeprovider.h"
#include <QPushButton>
#include <QPixmap>
#include <QLabel>

DashboardWidget::DashboardWidget(QWidget *parent) : QWidget(parent)
{
    this->setAutoFillBackground(true);

    QString flatstylesheet = QString("QPushButton:hover {"
                                         "background-color: %1;"
                                     "}").arg(this->palette().color(QPalette::Window).darker(125).name());

    this->setStyleSheet(flatstylesheet);
}

void DashboardWidget::makeBordered(QPushButton* pb) const
{
    static const QString borderedstylesheet = QString("QPushButton {"
                                                        "border-color: %1;"
                                                        "border-style: solid;"
                                                        "border-width: 1px;"
                                                      "}").arg(this->palette().color(QPalette::Text).name());

    pb->setStyleSheet(borderedstylesheet);
}

void DashboardWidget::applyLogo(QLabel* lbl) const
{
    if(ThemeProvider::isDarkTheme()) lbl->setPixmap(QPixmap(":/res/logo_dark.png"));
    else lbl->setPixmap(QPixmap(":/res/logo.png"));
}
