#include "rendererasync.h"
#include <QWidget>

RendererAsync::RendererAsync(const RDContextPtr& ctx, QObject* parent): QThread(parent), m_context(ctx) { }
RendererAsync::~RendererAsync() { this->abort(); }

void RendererAsync::abort()
{
    if(!this->isRunning() || m_abort.load()) return;

    {
        renderer_lock lock(m_mutex);
        m_abort.store(true);
        m_cv.notify_one();
    }

    this->wait();
}

void RendererAsync::schedule(Priority priority)
{
    if(this->isRunning())
    {
        if(m_painting.load()) return;
    }
    else
        this->start(priority);

    m_cv.notify_one();
}

QWidget* RendererAsync::widget() const { return static_cast<QWidget*>(this->parent()); }
bool RendererAsync::conditionWait() const { return true; }

void RendererAsync::run()
{
    while(!m_abort.load())
    {
        renderer_lock lock(m_mutex);
        m_cv.wait(lock, [&]() { return this->conditionWait() || m_abort.load(); });
        if(!this->conditionWait() || m_abort.load()) continue;

        m_painting.store(true);

        QImage img(this->widget()->size(), QImage::Format_RGB32);
        img.fill(this->widget()->palette().color(QPalette::Base));

        this->onRender(&img);
        emit renderCompleted(img);
        m_painting.store(false);
    }
}
