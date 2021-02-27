#pragma once

#include <QStandardItemModel>
#include <rdapi/rdapi.h>
#include "../../hooks/isurface.h"
#include "dashboardwidget.h"

namespace Ui {
class AnalysisWidget;
}

class AnalysisWidget : public DashboardWidget
{
    Q_OBJECT

    public:
        explicit AnalysisWidget(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~AnalysisWidget();

    private:
        void updateModel(QStandardItemModel* model, const char* const* namelist, size_t count, size_t current, const RDAnalysisStatus* s);
        void updateStats(const RDAnalysisStatus* s);
        void updateDiff(QStandardItem* item, int diff);

    private:
        static void updateState(const RDEventArgs* e);
        static QString printableDateDiff(const QDateTime& start, const QDateTime& end);
        static QString fileSize(double sz);

    Q_SIGNALS:
        void listingClicked();

    private:
        Ui::AnalysisWidget *ui;
        RDContextPtr m_context;
        QStandardItemModel *m_stepsmodel, *m_analyzersmodel, *m_statsmodel;
};
