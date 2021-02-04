#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>
#include "../hooks/isurface.h"

struct RDEventArgs;

class DisassemblerTabButton : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerTabButton(const RDContextPtr& ctx, QWidget* widget, QTabWidget* tabwidget, QWidget *parent = nullptr);
        virtual ~DisassemblerTabButton();

    private Q_SLOTS:
        void closeTab();

    private:
        QPushButton* createButton(const QIcon& icon);

    private:
        RDContextPtr m_context;
        QTabWidget* m_tabwidget;
        QWidget* m_widget;
};

