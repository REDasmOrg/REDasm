#pragma once

#include "dockwidget.h"

class SplitDockWidget: public DockWidget
{
    Q_OBJECT

    public:
        SplitDockWidget(QWidget* w, Options opt = Options(), LayoutSaverOptions lsp = LayoutSaverOptions());
        QAction* addButton(const QIcon& icon);
        QAction* action(int idx) const;
        QWidget* splitWidget() const;

    private:
        virtual SplitDockWidget* createSplit() const = 0;
        void createDefaultButtons();

    protected Q_SLOTS:
        void onDockShown() override;

    private Q_SLOTS:
        void splitHorizontal();
        void splitVertical();
        void splitInDialog();

    private:
        QAction* m_actfirstdefault{nullptr};
        QWidget *m_splitwidget{nullptr};
        QToolBar* m_tbactions;
};
