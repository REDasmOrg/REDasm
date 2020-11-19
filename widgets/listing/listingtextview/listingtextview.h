#pragma once

#include <QSplitter>
#include <rdapi/rdapi.h>
#include "listingpathwidget.h"
#include "listingtextwidget.h"

class ListingTextView : public QSplitter, public ISurface
{
    Q_OBJECT

    public:
        explicit ListingTextView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ListingPathWidget* columnWidget();
        ListingTextWidget* textWidget();

    public: // ISurface Implementation
        void copy() const override;
        void linkTo(ISurface* s) override;
        void unlink() override;
        void goBack() override;
        void goForward() override;
        bool goToAddress(rd_address address) override;
        bool goTo(const RDDocumentItem* item) override;
        bool seek(const RDDocumentItem* item) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        bool getCurrentItem(RDDocumentItem* item) const override;
        bool getCurrentSymbol(RDSymbol* symbol) const override;
        SurfaceQt* surface() const override;
        QString currentWord() const override;
        const RDContextPtr& context() const override;
        QWidget* widget() override;

    private:
        RDContextPtr m_context;
        ListingPathWidget* m_columnview;
        ListingTextWidget* m_textwidget;
};
