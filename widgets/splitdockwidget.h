#pragma once

#include <kddockwidgets/DockWidget.h>

class SplitDockWidget: public KDDockWidgets::DockWidget
{
    public:
        SplitDockWidget(QWidget* w, Options opt = DockWidgetBase::Options(), LayoutSaverOptions lsp = LayoutSaverOptions());
        QAction* addButton(const QIcon& icon);
        QAction* action(int idx) const;
        QWidget* splitWidget() const;

    private:
        virtual SplitDockWidget* createSplit() const = 0;
        void createDefaultButtons();

    private Q_SLOTS:
        void splitHorizontal();
        void splitVertical();
        void splitInDialog();

    private:
        QAction* m_actfirstdefault{nullptr};
        QToolBar* m_tbactions;
        QWidget *m_container, *m_splitwidget;
};
