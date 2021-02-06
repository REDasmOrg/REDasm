#include "dockwidget.h"
#include "../hooks/disassemblerhooks.h"

DockWidget::DockWidget(const QString& widgetid, Options opt, LayoutSaverOptions lsp): KDDockWidgets::DockWidget(widgetid, opt | DockWidget::Option_DeleteOnClose, lsp)
{
    m_action = DisassemblerHooks::instance()->addWindowAction(this);
    connect(this, &DockWidget::shown, this, &DockWidget::onDockShown);
}

DockWidget::~DockWidget() { DisassemblerHooks::instance()->removeWindowAction(m_action); }

void DockWidget::onDockShown() { if(this->isInMainWindow()) DisassemblerHooks::instance()->enableCommands(this->widget()); }
