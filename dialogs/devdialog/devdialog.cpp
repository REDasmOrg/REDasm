#include "devdialog.h"
#include "ui_devdialog.h"
#include "../renderer/surfaceqt.h"

DevDialog::DevDialog(const RDContextPtr& ctx, QWidget *parent) : QDialog(parent), ui(new Ui::DevDialog), m_context(ctx)
{
    ui->setupUi(this);
    ui->tabWidget->setStyleSheet("QTabWidget::pane { border: 0; }");

    RDObject_Subscribe(ctx.get(), this, [](const RDEventArgs* e) {
        switch(e->id) {
            case Event_ContextSurfaceChanged:
            case Event_SurfacePositionChanged: {
                auto* thethis = reinterpret_cast<DevDialog*>(e->owner);
                thethis->ui->tabDocument->updateInformation();
                thethis->ui->tabRDIL->updateInformation();
                break;
            }

            default: break;
        }
    }, nullptr);

    ui->tabDocument->setContext(ctx);
    ui->tabBlocks->setContext(ctx);
    ui->tabGraphs->setContext(ctx);
    ui->tabRDIL->setContext(ctx);
}

DevDialog::~DevDialog()
{
    if(m_context) RDObject_Unsubscribe(m_context.get(), this);
    delete ui;
}
