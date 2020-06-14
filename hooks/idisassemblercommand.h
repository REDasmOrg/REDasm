#pragma once

#include <QString>
#include <rdapi/rdapi.h>

class QWidget;

class IDisassemblerCommand
{
    public:
        virtual ~IDisassemblerCommand() = default;
        virtual void goBack() = 0;
        virtual void goForward() = 0;
        virtual void copy() const = 0;
        virtual bool gotoAddress(rd_address address) = 0;
        virtual bool gotoItem(const RDDocumentItem& item) = 0;
        virtual bool hasSelection() const = 0;
        virtual bool canGoBack() const = 0;
        virtual bool canGoForward() const = 0;
        virtual bool getCurrentItem(RDDocumentItem* item) const = 0;
        virtual bool getSelectedSymbol(RDSymbol* symbol) const = 0;
        virtual bool ownsCursor(const RDCursor* cursor) const = 0;
        virtual const RDCursorPos* currentPosition() const = 0;
        virtual const RDCursorPos* currentSelection() const = 0;
        virtual QString currentWord() const = 0;
        virtual RDDisassembler* disassembler() const = 0;
        virtual RDCursor* cursor() const = 0;
        virtual QWidget* widget() = 0;
};
