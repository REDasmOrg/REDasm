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
        ~DisassemblerTabButton();

    private slots:
        void closeTab();

    private:
        QPushButton* createButton(const QIcon& icon);
        QMenu* createMenu();
        void customizeBehavior();

    private:
        static void onCursorStackChanged(const RDEventArgs* e, void* userdata);

    private:
        QTabWidget* m_tabwidget;
        QWidget* m_widget;
        event_t m_cursorevent{0};
};

