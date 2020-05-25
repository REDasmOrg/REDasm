#include "disassemblertabbutton.h"
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QEvent>
#include <QMenu>
#include "../../hooks/disassemblerhooks.h"
#include "../../hooks/icommandtab.h"
#include "../../hooks/itabletab.h"
#include "../../redasmfonts.h"

DisassemblerTabButton::DisassemblerTabButton(QWidget* widget, QTabWidget* tabwidget, QWidget *parent) : QWidget(parent), m_tabwidget(tabwidget), m_widget(widget)
{
    QMenu* mnutab = this->createMenu();

    QLabel* lbltext = new QLabel(this);
    lbltext->setAlignment(Qt::AlignVCenter);
    lbltext->setText(widget->windowTitle());

    QPushButton* btnmenu = this->createButton(FA_ICON(0xf0c9));
    btnmenu->setMenu(mnutab);

    QHBoxLayout* hlayout = new QHBoxLayout();
    hlayout->addWidget(btnmenu);
    hlayout->addWidget(lbltext);
    hlayout->setContentsMargins(0, 0, 0, 0);
    hlayout->setSpacing(10);

    if(dynamic_cast<ICommandTab*>(widget)) hlayout->setStretch(2, 1);
    else hlayout->setStretch(hlayout->count() - 1, 1);

    this->setLayout(hlayout);
    this->customizeBehavior();
}

DisassemblerTabButton::~DisassemblerTabButton() { RDEvent_Unsubscribe(this); }

void DisassemblerTabButton::closeTab()
{
    for(int i = 0; i < m_tabwidget->count(); i++)
    {
        if(m_tabwidget->widget(i) != m_widget) continue;

        m_tabwidget->removeTab(i);
        break;
    }
}

QPushButton* DisassemblerTabButton::createButton(const QIcon& icon)
{
    QPushButton* btn = new QPushButton(this);
    btn->setFlat(true);
    btn->setIcon(icon);
    return btn;
}

void DisassemblerTabButton::customizeBehavior()
{
    RDEvent_Subscribe(this, [](const RDEventArgs* e, void* userdata) {
        auto* thethis = reinterpret_cast<DisassemblerTabButton*>(userdata);

        if((e->eventid == Event_CursorStackChanged) && dynamic_cast<ICommandTab*>(thethis->m_widget))
            thethis->onCursorStackChanged(e);

    }, this);
}

QMenu* DisassemblerTabButton::createMenu()
{
    QMenu* m = new QMenu(this);

    m->addAction("Close", this, &DisassemblerTabButton::closeTab);
    m->addAction("Detach");
    m->addAction("Duplicate");

    return m;
}

void DisassemblerTabButton::onCursorStackChanged(const RDEventArgs* e)
{
    auto* commandtab = dynamic_cast<ICommandTab*>(m_widget);
    if(!commandtab) return;

    RDCursor* cursor = reinterpret_cast<RDCursor*>(e->sender);
    if(!commandtab->command()->ownsCursor(cursor)) return;

    DisassemblerHooks::instance()->updateCommandStates(m_widget);
}
