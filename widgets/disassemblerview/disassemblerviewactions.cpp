#include "disassemblerviewactions.h"
#include "../../themeprovider.h"
#include <QApplication>

DisassemblerViewActions::DisassemblerViewActions(QObject *parent) : QObject(parent)
{
    for(const auto* widget : qApp->topLevelWidgets())
    {
        m_toolbar = widget->findChild<QToolBar*>("toolBar");
        if(m_toolbar) break;
    }

    this->initActions();
}

void DisassemblerViewActions::setIcon(int actionid, const QIcon &icon)
{
    if(!m_actions.contains(actionid)) return;
    m_actions[actionid]->setIcon(icon);
}

void DisassemblerViewActions::setEnabled(int actionid, bool b)
{
    if(!m_actions.contains(actionid)) return;
    m_actions[actionid]->setEnabled(b);
}

void DisassemblerViewActions::setVisible(int actionid, bool b)
{
    if(!m_actions.contains(actionid)) return;
    m_actions[actionid]->setEnabled(b);
    m_actions[actionid]->setVisible(b);
}

void DisassemblerViewActions::findActions(const std::function<void(QAction*)>& cb)
{
    if(!m_toolbar)
        return;

    QList<QAction*> actions = m_toolbar->actions();
    auto it = std::find_if(actions.begin(), actions.end(), [](QAction* a) -> bool { return a->isSeparator(); });

    for(; it != actions.end(); it++)
        cb(*it);
}

void DisassemblerViewActions::initActions()
{
    this->findActions([&](QAction* a) {
        if(a->isSeparator()) m_separators.push_back(a);
        else if(a->objectName().endsWith("Back")) this->showAction(DisassemblerViewActions::BackAction, a, THEME_ICON("back"), &DisassemblerViewActions::backRequested);
        else if(a->objectName().endsWith("Forward")) this->showAction(DisassemblerViewActions::ForwardAction, a, THEME_ICON("forward"), &DisassemblerViewActions::forwardRequested);
        else if(a->objectName().endsWith("Goto")) this->showAction(DisassemblerViewActions::GotoAction, a, THEME_ICON("goto"), &DisassemblerViewActions::gotoRequested);
        else if(a->objectName().endsWith("Graph")) this->showAction(DisassemblerViewActions::GraphListingAction, a, THEME_ICON("graph"), &DisassemblerViewActions::graphListingRequested);
    });
}

void DisassemblerViewActions::hideActions()
{
    for(auto it = m_actions.begin(); it != m_actions.end(); it++) (*it)->setVisible(false);
    for(auto it = m_separators.begin(); it != m_separators.end(); it++) (*it)->setVisible(false);
}
