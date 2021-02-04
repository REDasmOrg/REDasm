#pragma once

#include <QThread>
#include <QImage>
#include <condition_variable>
#include <atomic>
#include <mutex>
#include "../hooks/isurface.h"

class RendererAsync: public QThread
{
    Q_OBJECT

    private:
        typedef std::unique_lock<std::mutex> renderer_lock;

    public:
        RendererAsync(const RDContextPtr& ctx, QObject* parent);
        virtual ~RendererAsync();
        void abort();

    Q_SIGNALS:
        void renderCompleted(const QImage& image);

    protected:
        QWidget* widget() const;
        virtual bool conditionWait() const;
        virtual void onRender(QImage* image) = 0;
        void schedule(QThread::Priority priority = InheritPriority);
        void run() override;

    protected:
        RDContextPtr m_context;

    private:
        std::atomic_bool m_abort{false}, m_painting{false};
        std::condition_variable m_cv;
        std::mutex m_mutex;
};

