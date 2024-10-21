#pragma once

#include <kddockwidgets/DockWidget.h>

class DockWidget: public KDDockWidgets::DockWidget {
    Q_OBJECT

public:
    explicit DockWidget(const QString& widgetid,
                        Options opt = DockWidget::Options(),
                        LayoutSaverOptions lsp = LayoutSaverOptions());
    ~DockWidget() override;

protected Q_SLOTS:
    virtual void onDockShown();

private:
    QAction* m_action;
};
