#include "splitdockwidget.h"
#include "../../redasmfonts.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../hooks/dockidentifiers.h"
#include <QVBoxLayout>
#include <QSplitter>
#include <QToolBar>

SplitDockWidget::SplitDockWidget(QWidget* w, Options opt, LayoutSaverOptions lsp): DockWidget(DockIdentifiers::getId(w), opt, lsp), m_splitwidget(w)
{
    m_tbactions = new QToolBar();
    m_tbactions->setIconSize({16, 16});
    m_tbactions->setToolButtonStyle(Qt::ToolButtonIconOnly);
    this->createDefaultButtons();

    auto* lcontent = new QVBoxLayout();
    lcontent->setSpacing(0);
    lcontent->setContentsMargins(0, 0, 0, 0);
    lcontent->addWidget(m_tbactions);
    lcontent->addWidget(w);

    QWidget* cw = new QWidget();
    cw->setLayout(lcontent);

    this->setWidget(cw);
}

QAction* SplitDockWidget::addButton(const QIcon& icon)
{
    auto* act = new QAction(icon, QString(), m_tbactions);
    m_tbactions->insertAction(m_actfirstdefault, act);
    return act;
}

QAction* SplitDockWidget::action(int idx) const
{
    auto actions = m_tbactions->actions();
    return actions.at(idx);
}

QWidget* SplitDockWidget::splitWidget() const { return m_splitwidget; }

void SplitDockWidget::createDefaultButtons()
{
    QWidget* empty = new QWidget();
    empty->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_actfirstdefault = m_tbactions->addWidget(empty);
    connect(m_tbactions->addAction(FA_ICON(0xf105), QString()), &QAction::triggered, this, &SplitDockWidget::splitHorizontal);
    connect(m_tbactions->addAction(FA_ICON(0xf107), QString()), &QAction::triggered, this, &SplitDockWidget::splitVertical);
    connect(m_tbactions->addAction(FA_ICON(0xf2d2), QString()), &QAction::triggered, this, &SplitDockWidget::splitInDialog);
}

void SplitDockWidget::onDockShown() { if(this->isInMainWindow()) DisassemblerHooks::instance()->enableCommands(m_splitwidget); }

void SplitDockWidget::splitHorizontal()
{
    auto* dock = this->createSplit();
    if(dock) DisassemblerHooks::mainWindow()->addDockWidget(dock, KDDockWidgets::Location_OnRight, this);
}

void SplitDockWidget::splitVertical()
{
    auto* dock = this->createSplit();
    if(dock) DisassemblerHooks::mainWindow()->addDockWidget(dock, KDDockWidgets::Location_OnBottom, this);
}

void SplitDockWidget::splitInDialog()
{
    auto* dock = this->createSplit();
    dock->show();
}
