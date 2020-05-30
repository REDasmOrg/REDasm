#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>
#include <rdapi/rdapi.h>

class DisassemblerTabButton : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabButton(QWidget* widget, QTabWidget* tabwidget, QWidget *parent = nullptr);
        virtual ~DisassemblerTabButton();

    private slots:
        void closeTab();

    private:
        void onCursorStackChanged(const RDEventArgs* e);
        QPushButton* createButton(const QIcon& icon);
        void customizeBehavior();

    private:
        QTabWidget* m_tabwidget;
        QWidget* m_widget;
};

