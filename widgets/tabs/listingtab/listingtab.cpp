#include "listingtab.h"
#include "../../../themeprovider.h"
#include "../../../redasmsettings.h"
#include "../../../redasmfonts.h"
#include <QVBoxLayout>
#include <QKeyEvent>

ListingTab::ListingTab(const RDDisassemblerPtr& disassembler, QWidget* parent) : QWidget(parent)
{
    this->setWindowTitle("Listing");

    m_listingview = new DisassemblerListingView(disassembler, this);

    m_graphview = new DisassemblerGraphView(m_listingview->textView(), this);
    m_graphview->setVisible(false);

    QVBoxLayout* vl = new QVBoxLayout();
    vl->setContentsMargins(0, 0, 0, 0);
    vl->addWidget(m_listingview);
    vl->addWidget(m_graphview);
    this->setLayout(vl);

    m_graphview->installEventFilter(this);
    m_listingview->textView()->installEventFilter(this);
    m_listingview->textView()->setFocus();
}

IDisassemblerCommand* ListingTab::command() const
{
    if(m_graphview->isVisible()) return m_graphview;
    return m_listingview->textView();
}

QWidget* ListingTab::widget() { return this; }

void ListingTab::switchToGraph()
{
    m_listingview->setVisible(false);

    m_graphview->renderGraph();
    m_graphview->setVisible(true);
    m_graphview->setFocus();
}

void ListingTab::switchToListing()
{
    m_graphview->setVisible(false);
    m_listingview->setVisible(true);
    m_listingview->textView()->setFocus();
}

void ListingTab::switchMode()
{
    if(m_graphview->isVisible()) this->switchToListing();
    else this->switchToGraph();
}

bool ListingTab::eventFilter(QObject* object, QEvent* event)
{
    if(((object == m_listingview->textView()) || (object == m_graphview)) && (event->type() == QEvent::KeyPress))
    {
        QKeyEvent* keyevent = static_cast<QKeyEvent*>(event);

        if(keyevent->key() == Qt::Key_Space)
        {
            this->switchMode();
            return true;
        }
    }

    return false;
}
