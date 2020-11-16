#include "listingview.h"

ListingView::ListingView(const RDContextPtr& ctx, QWidget *parent) : QStackedWidget(parent), m_context(ctx)
{
    m_textview = new ListingTextView(ctx);
    m_graphview = new ListingGraphView(ctx);

    this->addWidget(m_textview);
    this->addWidget(m_graphview);

    m_graphview->installEventFilter(this);
    m_textview->textWidget()->installEventFilter(this);
    m_textview->textWidget()->setFocus();
}

bool ListingView::getCurrentItem(RDDocumentItem* item)
{
    auto* isurface = dynamic_cast<ISurface*>(this->currentWidget());
    return isurface ? isurface->getCurrentItem(item) : false;
}

void ListingView::switchToGraph()
{
    RDDocumentItem item;
    if(!this->getCurrentItem(&item)) return;

    this->setCurrentWidget(m_graphview);
    m_graphview->renderGraph(&item);
    m_graphview->setFocus();
}

void ListingView::switchToListing()
{
    RDDocumentItem item;
    if(!this->getCurrentItem(&item)) return;

    m_textview->textWidget()->goTo(&item);
    this->setCurrentWidget(m_textview);
    m_textview->textWidget()->setFocus();
}

void ListingView::switchMode()
{
    if(m_graphview->isVisible()) this->switchToListing();
    else this->switchToGraph();
}

bool ListingView::eventFilter(QObject* object, QEvent* event)
{
    if(((object == m_textview->textWidget()) || (object == m_graphview)) && (event->type() == QEvent::KeyPress))
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
