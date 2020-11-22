#include "disassemblertabbutton.h"
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QEvent>
#include <QMenu>
#include <rdapi/rdapi.h>
#include "../../hooks/disassemblerhooks.h"
#include "../../redasmfonts.h"

DisassemblerTabButton::DisassemblerTabButton(const RDContextPtr& ctx, QWidget* widget, QTabWidget* tabwidget, QWidget *parent) : QWidget(parent), m_context(ctx), m_tabwidget(tabwidget), m_widget(widget)
{
    QLabel* lbltext = new QLabel(this);
    lbltext->setAlignment(Qt::AlignCenter);
    lbltext->setText(widget->windowTitle());

    QHBoxLayout* hlayout = new QHBoxLayout();
    hlayout->addWidget(lbltext);
    hlayout->setContentsMargins(10, 0, 0, 0);
    hlayout->setSpacing(10);
    hlayout->setStretch(hlayout->count() - 1, 1);

    this->setLayout(hlayout);
}

DisassemblerTabButton::~DisassemblerTabButton() { RDObject_Unsubscribe(m_context.get(), this); }

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
