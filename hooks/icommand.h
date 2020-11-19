#pragma once

#include <QString>
#include <memory>
#include <rdapi/rdapi.h>

class QWidget;
class SurfaceQt;

typedef std::shared_ptr<RDContext> RDContextPtr;

class ISurface
{
    public:
        virtual ~ISurface() = default;
        virtual void copy() const = 0;
        virtual void linkTo(ISurface* s) = 0;
        virtual void unlink() = 0;
        virtual void goBack() = 0;
        virtual void goForward() = 0;
        virtual bool goToAddress(rd_address address) = 0;
        virtual bool seek(const RDDocumentItem* item) = 0;
        virtual bool goTo(const RDDocumentItem* item) = 0;
        virtual bool hasSelection() const = 0;
        virtual bool canGoBack() const = 0;
        virtual bool canGoForward() const = 0;
        virtual bool getCurrentItem(RDDocumentItem* item) const = 0;
        virtual bool getCurrentSymbol(RDSymbol* symbol) const = 0;
        virtual SurfaceQt* surface() const = 0;
        virtual QString currentWord() const = 0;
        virtual const RDContextPtr& context() const = 0;
        virtual QWidget* widget() = 0;
};
