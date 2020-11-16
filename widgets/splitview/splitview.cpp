#include "splitview.h"
#include <QVBoxLayout>

SplitView::SplitView(QWidget *parent) : QWidget(parent)
{
    m_layout = new QVBoxLayout();
    m_layout->setMargin(0);
    m_layout->setSpacing(0);
    this->setLayout(m_layout);
}

void SplitView::createFirst()
{
    auto* si = new SplitItem(this->createWidget(), this, this);
    si->setCanClose(false);
    m_layout->addWidget(si);
}

void SplitView::onItemSplit(const SplitItem* item, const SplitItem* newitem) const { }
void SplitView::onItemCreated(SplitItem* item) const { }
