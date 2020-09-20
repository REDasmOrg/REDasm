#include "disassemblertabs.h"
#include "disassemblertabbutton.h"
#include "../hooks/disassemblerhooks.h"
#include "../hooks/icommandtab.h"
#include "../redasmfonts.h"
#include <QTabBar>

DisassemblerTabs::DisassemblerTabs(const RDDisassemblerPtr& disassembler, QWidget *parent) : QTabWidget(parent), m_disassembler(disassembler)
{
    this->setTabBarAutoHide(true);
    this->setMovable(true);

    connect(this, &DisassemblerTabs::currentChanged, this, &DisassemblerTabs::onTabChanged);
}

int DisassemblerTabs::tabHeight() const { return 25; }

void DisassemblerTabs::tabInserted(int index)
{
    this->setTabText(index, QString());
    this->tabBar()->setTabButton(index, QTabBar::LeftSide, new DisassemblerTabButton(m_disassembler, this->widget(index), this));

    QPushButton* btnclose = new QPushButton();
    btnclose->setFlat(true);
    btnclose->setIcon(FA_ICON(0xf00d));

    this->tabBar()->setTabButton(index, QTabBar::RightSide, btnclose);
    connect(btnclose, &QPushButton::clicked, this, &DisassemblerTabs::onCloseClicked);

    QTabWidget::tabInserted(index);
}

void DisassemblerTabs::onTabChanged(int index)
{
    QWidget* w = this->widget(index);

    if(auto* commandtab = dynamic_cast<ICommandTab*>(w))
        DisassemblerHooks::instance()->setActiveCommandTab(commandtab);

    DisassemblerHooks::instance()->enableCommands(w);
    DisassemblerHooks::instance()->updateCommandStates(w);
}

void DisassemblerTabs::onCloseClicked()
{
    auto* sender = static_cast<QPushButton*>(this->sender());

    for(int i = 0; i < this->tabBar()->count(); i++)
    {
        if(this->tabBar()->tabButton(i, QTabBar::RightSide) != sender) continue;

        auto* commandtab = dynamic_cast<ICommandTab*>(this->widget(i));

        if(commandtab && (DisassemblerHooks::instance()->activeCommandTab() == commandtab))
            DisassemblerHooks::instance()->setActiveCommandTab(nullptr);

        this->removeTab(i);
        break;
    }
}
