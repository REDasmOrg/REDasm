#pragma once

#include <QString>
#include <memory>
#include <rdapi/rdapi.h>

#define DEFAULT_DIALOG_WIDTH  640
#define DEFAULT_DIALOG_HEIGHT 480

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
        virtual bool seek(rd_address address) = 0;
        virtual bool goTo(rd_address address) = 0;
        virtual bool hasSelection() const = 0;
        virtual bool canGoBack() const = 0;
        virtual bool canGoForward() const = 0;
        virtual rd_address currentAddress() const = 0;
        virtual QString currentLabel(rd_address* address) const = 0;
        virtual QString currentWord() const = 0;
        virtual SurfaceQt* surface() const = 0;
        virtual const RDContextPtr& context() const = 0;
        virtual QWidget* widget() = 0;
};
