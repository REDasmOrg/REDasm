#include "flcdialog.h"
#include "ui_flcdialog.h"
#include <QRegularExpressionValidator>
#include <QRegularExpression>
#include <QClipboard>
#include <QLineEdit>
#include <iostream>

FLCDialog::FLCDialog(QWidget *parent) : QDialog(parent), ui(new Ui::FLCDialog)
{
    ui->setupUi(this);
    this->setFixedSize(this->size());

    QRegularExpression rgx("[a-fA-F0-9]*");
    ui->leAddress->setValidator(new QRegularExpressionValidator(rgx, this));
    ui->leOffset->setValidator(new QRegularExpressionValidator(rgx, this));

    connect(ui->pbCopyAddress, &QPushButton::clicked, this, [=]() {
        QString s = ui->leAddress->text();
        if(!s.isEmpty()) qApp->clipboard()->setText(s);
    });

    connect(ui->pbCopyOffset, &QPushButton::clicked, this, [=]() {
        QString s = ui->leOffset->text();
        if(!s.isEmpty()) qApp->clipboard()->setText(s);
    });

    connect(ui->pbCopySegment, &QPushButton::clicked, this, [=]() {
        qApp->clipboard()->setText(ui->leSegment->text());
    });

    connect(ui->leAddress, &QLineEdit::textChanged, this, [=]() {
        if(ui->leOffset->hasFocus() || !m_context) return;

        auto* doc = RDContext_GetDocument(m_context.get());

        bool ok = true;
        auto val = ui->leAddress->text().toULongLong(&ok, 16);
        auto loc = ok ? RD_Offset(m_context.get(), val) : RDLocation{ };

        if(ok && loc.valid) {
            ui->leOffset->setText(loc.valid ? RD_ToHex(loc.offset) : QString());

            RDSegment segment;
            ok = RDDocument_OffsetToSegment(doc, loc.offset, &segment);
            if(ok) ui->leSegment->setText(QString::fromUtf8(segment.name));
            else ui->leSegment->setText(QString());
            ui->pbCopySegment->setEnabled(ok);
        }
        else {
            ui->leOffset->setText(QString());
            ui->leSegment->setText(QString());
            ui->pbCopySegment->setEnabled(false);
        }
    });

    connect(ui->leOffset, &QLineEdit::textChanged, this, [=]() {
        if(ui->leAddress->hasFocus() || !m_context) return;

        auto* doc = RDContext_GetDocument(m_context.get());

        bool ok = false;
        auto val = ui->leOffset->text().toULongLong(&ok, 16);
        auto loc = ok ? RD_Address(m_context.get(), val) : RDLocation{ };

        if(ok && loc.valid) {
            ui->leAddress->setText(loc.valid ? RD_ToHex(loc.address) : QString());

            RDSegment segment;
            ok = RDDocument_AddressToSegment(doc, loc.address, &segment);
            if(ok) ui->leSegment->setText(QString::fromUtf8(segment.name));
            else ui->leSegment->setText(QString());
            ui->pbCopySegment->setEnabled(ok);
        }
        else {
            ui->leAddress->setText(QString());
            ui->leSegment->setText(QString());
            ui->pbCopySegment->setEnabled(false);
        }
    });
}

FLCDialog::~FLCDialog() { delete ui; }

void FLCDialog::showFLC(const RDContextPtr& ctx)
{
    m_context = ctx;

    auto w = static_cast<int>(RDContext_GetAddressWidth(ctx.get()) * 2);
    ui->leAddress->setMaxLength(w);
    ui->leOffset->setMaxLength(w);
    this->show();
}

void FLCDialog::closeEvent(QCloseEvent* e)
{
    QDialog::closeEvent(e);

    m_context = nullptr;
    ui->leAddress->clear();
    ui->leOffset->clear();
    ui->leSegment->clear();
}
