#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>
#include "../hooks/icommand.h"

struct RDEventArgs;

class DisassemblerTabButton : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabButton(const RDContextPtr& ctx, QWidget* widget, QTabWidget* tabwidget, QWidget *parent = nullptr);
        virtual ~DisassemblerTabButton();

    private slots:
        void closeTab();

    private:
        void onStackChanged(const RDEventArgs* e);
        QPushButton* createButton(const QIcon& icon);
        void customizeBehavior();

    private:
        RDContextPtr m_context;
        QTabWidget* m_tabwidget;
        QWidget* m_widget;
};

