#include "splitview.h"
#include <QVBoxLayout>
#include <QDialog>

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

void SplitView::checkCanClose() { for(auto& si : m_items) si->setCanClose((m_items.size() > 1)); }

SplitItem* SplitView::splitItem(QWidget* w) const
{
    auto it = m_items.find(w);
    return (it != m_items.end()) ? it.value() : nullptr;
}

QDialog* SplitView::createDialog(QWidget* parent) const { return new QDialog(parent); }
SplitView* SplitView::createView() const { return new SplitView(); }
QWidget* SplitView::createWidget() { return new QWidget(); }

void SplitView::onItemSplit(SplitItem* item, SplitItem* newitem)
{
    m_items[item->widget()] = item;
    m_items[newitem->widget()] = newitem;
}

void SplitView::onItemDestroyed(const SplitItem* item)
{
    m_items.remove(item->widget());
    this->checkCanClose();
}

void SplitView::onItemCreated(SplitItem* item)
{
    m_items[item->widget()] = item;
    this->checkCanClose();
}
