#include "analysiswidget.h"
#include "ui_analysiswidget.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../themeprovider.h"
#include <QDateTime>

AnalysisWidget::AnalysisWidget(const RDContextPtr& ctx, QWidget *parent) : DashboardWidget(parent), ui(new Ui::AnalysisWidget), m_context(ctx)
{
    static const std::vector<QString> STATS_ROWS = {
        "Analysis Start", "Analysis End", "Analysis Time",
        "Segments", "Functions", "Symbols"
    };

    DisassemblerHooks::instance()->setTabBarVisible(false);

    ui->setupUi(this);
    this->setWindowTitle("Analysis");
    this->makeBordered(ui->pbShowListing);

    ui->lvSteps->viewport()->setBackgroundRole(QPalette::Window);
    ui->lvAnalyzers->viewport()->setBackgroundRole(QPalette::Window);
    ui->tbvStats->viewport()->setBackgroundRole(QPalette::Window);

    m_stepsmodel = new QStandardItemModel(ui->lvSteps);
    m_analyzersmodel = new QStandardItemModel(ui->lvAnalyzers);
    m_statsmodel = new QStandardItemModel(ui->tbvStats);
    m_statsmodel->setColumnCount(3);

    for(const QString& s : STATS_ROWS)
        m_statsmodel->appendRow({ new QStandardItem(s), new QStandardItem(""), new QStandardItem("") });

    ui->lvSteps->setAttribute(Qt::WA_TransparentForMouseEvents);
    ui->lvSteps->setFocusPolicy(Qt::NoFocus);
    ui->lvSteps->setModel(m_stepsmodel);

    ui->lvAnalyzers->setAttribute(Qt::WA_TransparentForMouseEvents);
    ui->lvAnalyzers->setFocusPolicy(Qt::NoFocus);
    ui->lvAnalyzers->setModel(m_analyzersmodel);

    ui->tbvStats->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tbvStats->setAttribute(Qt::WA_TransparentForMouseEvents);
    ui->tbvStats->setFocusPolicy(Qt::NoFocus);
    ui->tbvStats->setModel(m_statsmodel);

    ui->pbShowListing->setCursor(Qt::PointingHandCursor);
    connect(ui->pbShowListing, &QPushButton::clicked, this, &AnalysisWidget::listingClicked);

    RDObject_Subscribe(m_context.get(), this, [](const RDEventArgs* e) {
        if(e->id == Event_AnalysisStatusChanged) AnalysisWidget::updateState(e);
    }, nullptr);
}

AnalysisWidget::~AnalysisWidget() { RDObject_Unsubscribe(m_context.get(), this); delete ui; }

void AnalysisWidget::updateModel(QStandardItemModel* model, const char* const* namelist, size_t count, size_t current, const RDAnalysisStatus* s)
{
    if(!model->rowCount())
    {
        for(size_t i = 0; i < count; i++)
        {
            auto* item = new QStandardItem(namelist[i]);
            item->setCheckable(true);
            model->appendRow(item);
        }
    }

    for(size_t i = 0; i < count; i++)
    {
        auto* item = model->item(i);

        if(model == m_analyzersmodel) item->setText(QString("%1 x  %2").arg(s->analyzersdone[i]).arg(namelist[i]));

        if(i == current)
        {
            item->setCheckState(Qt::Checked);

            if((model == m_analyzersmodel) && s->analyzersdone[i]) item->setForeground(THEME_VALUE(Theme_GraphEdgeLoop));
            else item->setForeground(THEME_VALUE(Theme_Success));
        }
        else
        {
            item->setCheckState(Qt::Unchecked);

            if((model == m_analyzersmodel) && s->analyzersdone[i]) item->setForeground(THEME_VALUE(Theme_GraphEdgeLoop));
            else item->setForeground(THEME_VALUE(Theme_Fail));
        }
    }
}

void AnalysisWidget::updateStats(const RDAnalysisStatus* s)
{
    m_statsmodel->item(0, 1)->setText(QDateTime::fromTime_t(static_cast<time_t>(s->analysisstart)).toString());
    auto *item = m_statsmodel->item(1, 1), *timeitem = m_statsmodel->item(2, 1);

    if(s->analysisend)
    {
        QDateTime start = QDateTime::fromTime_t(static_cast<time_t>(s->analysisstart));
        QDateTime end = QDateTime::fromTime_t(static_cast<time_t>(s->analysisend));
        item->setText(end.toString());

        timeitem->setText(AnalysisWidget::printableDateDiff(start, end));
        item->setForeground(THEME_VALUE(Theme_Success));
    }
    else
    {
        m_statsmodel->item(1, 1)->setText("In Progress");
        m_statsmodel->item(2, 1)->setText("In Progress");
        timeitem->setForeground(THEME_VALUE(Theme_GraphEdgeLoop));
        item->setForeground(THEME_VALUE(Theme_GraphEdgeLoop));
    }

    m_statsmodel->item(3, 1)->setText(QString::number(s->segmentscount));
    m_statsmodel->item(4, 1)->setText(QString::number(s->functionscount));
    m_statsmodel->item(5, 1)->setText(QString::number(s->symbolscount));

    this->updateDiff(m_statsmodel->item(3, 2), s->segmentsdiff);
    this->updateDiff(m_statsmodel->item(4, 2), s->functionsdiff);
    this->updateDiff(m_statsmodel->item(5, 2), s->symbolsdiff);
}

void AnalysisWidget::updateDiff(QStandardItem* item, int diff)
{
    if(diff > 0)
    {
        item->setText(QString("+%1").arg(diff));
        item->setForeground(THEME_VALUE(Theme_Success));
    }
    else if(diff < 0)
    {
        item->setText(QString("%1").arg(diff));
        item->setForeground(THEME_VALUE(Theme_Fail));
    }
    else
        item->setText(QString());
}

QString AnalysisWidget::fileSize(double sz)
{
    static const QStringList UNITS = { "KB", "MB", "GB", "TB" };
    QStringListIterator i(UNITS);
    QString unit = "bytes";

    while((sz >= 1024.0) && i.hasNext())
    {
        unit = i.next();
        sz /= 1024.0;
    }

    return QString("%1 %2").arg(sz, 0, 'f', 2).arg(unit);
}

void AnalysisWidget::updateState(const RDEventArgs* e)
{
    auto* thethis = reinterpret_cast<AnalysisWidget*>(e->owner);
    auto* s = reinterpret_cast<const RDAnalysisStatusEventArgs*>(e)->status;

    thethis->ui->pbShowListing->setVisible(!s->busy);
    thethis->ui->lblFilePath->setText(QString::fromUtf8(s->filepath));
    thethis->ui->lblAssembler->setText(QString::fromUtf8(s->assembler));
    thethis->ui->lblLoader->setText(QString::fromUtf8(s->loader));
    thethis->ui->lblFileSize->setText(AnalysisWidget::fileSize(static_cast<double>(s->filesize)));

    thethis->updateModel(thethis->m_stepsmodel, s->stepslist, s->stepscount, s->stepscurrent, s);
    thethis->updateModel(thethis->m_analyzersmodel, s->analyzerslist, s->analyzerscount, s->analyzerscurrent, s);
    thethis->updateStats(s);
}

QString AnalysisWidget::printableDateDiff(const QDateTime& start, const QDateTime& end)
{
    auto days = start.daysTo(end);
    if(days > 1) return QString("%d days").arg(days);

    QTime t(0, 0);
    t = t.addSecs(start.secsTo(end));
    auto s = t.toString("hh:mm:ss");
    return s;
}
