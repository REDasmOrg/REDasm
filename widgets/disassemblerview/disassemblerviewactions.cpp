#include "disassemblerviewactions.h"
#include "../../themeprovider.h"
#include <QApplication>

DisassemblerViewActions::DisassemblerViewActions(QObject *parent) : QObject(parent)
{
    for(const auto* widget : qApp->topLevelWidgets())
    {
        m_toolbar = widget->findChild<QToolBar*>("toolBar");

        if(m_toolbar)
            break;
    }

    this->addActions();
}

void DisassemblerViewActions::setIcon(int actionid, const QIcon &icon)
{
    if(!m_actions.contains(actionid))
        return;

    m_actions[actionid]->setIcon(icon);
}

void DisassemblerViewActions::setEnabled(int actionid, bool b)
{
    if(!m_actions.contains(actionid))
        return;

    m_actions[actionid]->setEnabled(b);
}

void DisassemblerViewActions::setVisible(int actionid, bool b)
{
    if(!m_actions.contains(actionid))
        return;

    m_actions[actionid]->setEnabled(b);
    m_actions[actionid]->setVisible(b);
}

DisassemblerViewActions::~DisassemblerViewActions() { this->removeActions(); }
void DisassemblerViewActions::addSeparator() { m_separators.push_back(m_toolbar->addSeparator()); }

void DisassemblerViewActions::addActions()
{
    if(!m_toolbar)
        return;

    this->addSeparator();

    m_actions[DisassemblerViewActions::BackAction] = m_toolbar->addAction(THEME_ICON("back"), QString(),
                                                                          this, &DisassemblerViewActions::backRequested);

    m_actions[DisassemblerViewActions::ForwardAction] = m_toolbar->addAction(THEME_ICON("forward"), QString(),
                                                                             this, &DisassemblerViewActions::forwardRequested);

    m_actions[DisassemblerViewActions::GotoAction] = m_toolbar->addAction(THEME_ICON("goto"), QString(),
                                                                          this, &DisassemblerViewActions::gotoRequested);

    m_actions[DisassemblerViewActions::GraphListingAction] = m_toolbar->addAction(THEME_ICON("graph"), QString(),
                                                                                  this, &DisassemblerViewActions::graphListingRequested);
}

void DisassemblerViewActions::removeActions()
{
    for(auto it = m_actions.begin(); it != m_actions.end(); )
    {
        m_toolbar->removeAction(it.value());
        it = m_actions.erase(it);
    }

    while(!m_separators.empty())
    {
        m_toolbar->removeAction(m_separators.front());
        m_separators.pop_front();
    }
}
