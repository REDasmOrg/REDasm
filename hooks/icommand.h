#pragma once

#include <QString>
#include <memory>
#include <rdapi/rdapi.h>

class QWidget;
class SurfaceRenderer;

typedef std::shared_ptr<RDContext> RDContextPtr;

class ICommand
{
    public:
        virtual ~ICommand() = default;
        virtual void goBack() = 0;
        virtual void goForward() = 0;
        virtual void copy() const = 0;
        virtual bool goToAddress(rd_address address) = 0;
        virtual bool goTo(const RDDocumentItem& item) = 0;
        virtual bool hasSelection() const = 0;
        virtual bool canGoBack() const = 0;
        virtual bool canGoForward() const = 0;
        virtual bool getCurrentItem(RDDocumentItem* item) const = 0;
        virtual bool getSelectedSymbol(RDSymbol* symbol) const = 0;
        virtual const RDSurfacePos* currentPosition() const = 0;
        virtual const RDSurfacePos* currentSelection() const = 0;
        virtual const RDDocumentItem* firstItem() const = 0;
        virtual const RDDocumentItem* lastItem() const = 0;
        virtual SurfaceRenderer* surface() const = 0;
        virtual QString currentWord() const = 0;
        virtual const RDContextPtr& context() const = 0;
        virtual QWidget* widget() = 0;

    public:
        inline RDDisassembler* disassembler() const { return RDContext_GetDisassembler(this->context().get()); }
};
