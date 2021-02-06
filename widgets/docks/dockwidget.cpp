#include "dockwidget.h"
#include "../hooks/disassemblerhooks.h"

DockWidget::DockWidget(const QString& widgetid, Options opt, LayoutSaverOptions lsp): KDDockWidgets::DockWidget(widgetid, opt | DockWidget::Option_DeleteOnClose, lsp)
{
    connect(this, &DockWidget::shown, this, &DockWidget::onDockShown);
}

void DockWidget::onDockShown() { if(this->isInMainWindow()) DisassemblerHooks::instance()->enableCommands(this->widget()); }
