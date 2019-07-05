#include "iteminformationdialog.h"
#include "ui_iteminformationdialog.h"
#include "../../../redasmsettings.h"
#include "../logsyntaxhighlighter.h"
#include "../convert.h"
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/support/utils.h>

#define ITEM_TYPE(x)  #x
#define HEADER_STRING "="
#define HEADER_WIDTH  20
#define HEADER_PART   QString(HEADER_STRING).repeated(HEADER_WIDTH)

ItemInformationDialog::ItemInformationDialog(const REDasm::DisassemblerPtr &disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::ItemInformationDialog), m_disassembler(disassembler)
{
    ui->setupUi(this);
    ui->pteInfo->setFont(REDasmSettings::font());

    new LogSyntaxHighlighter(ui->pteInfo->document());
    this->displayInformation();
}

ItemInformationDialog::~ItemInformationDialog() { delete ui; }
ItemInformationDialog &ItemInformationDialog::line(const QString &s1, const QString &s2) { return this->line(s1 + ": " + s2); }
ItemInformationDialog& ItemInformationDialog::line(const QString &s) { ui->pteInfo->appendPlainText(s); return *this; }

ItemInformationDialog &ItemInformationDialog::header(const QString &s)
{
    QString hdr = HEADER_PART;

    if(!s.isEmpty())
        hdr += QString(" %1 ").arg(s);

    hdr += HEADER_PART;
    return this->line(hdr);
}

ItemInformationDialog &ItemInformationDialog::string(const QString &k, const QString &s) { return this->line(k, QString("\"%1\"").arg(s)); }

QString ItemInformationDialog::itemType(const REDasm::ListingItem *item) const
{
    if(item->type() == REDasm::ListingItemType::SegmentItem)
        return ITEM_TYPE(REDasm::ListingItem::SegmentItem);
    if(item->type() == REDasm::ListingItemType::EmptyItem)
        return ITEM_TYPE(REDasm::ListingItem::EmptyItem);
    if(item->type() == REDasm::ListingItemType::FunctionItem)
        return ITEM_TYPE(REDasm::ListingItem::FunctionItem);
    if(item->type() == REDasm::ListingItemType::TypeItem)
        return ITEM_TYPE(REDasm::ListingItem::TypeItem);
    if(item->type() == REDasm::ListingItemType::SymbolItem)
        return ITEM_TYPE(REDasm::ListingItem::SymbolItem);
    if(item->type() == REDasm::ListingItemType::MetaItem)
        return ITEM_TYPE(REDasm::ListingItem::MetaItem);
    if(item->type() == REDasm::ListingItemType::InstructionItem)
        return ITEM_TYPE(REDasm::ListingItem::InstructionItem);

    return QString::number(static_cast<size_t>(item->type()));
}

void ItemInformationDialog::displayInformation()
{
    const auto& document = m_disassembler->document();
    const REDasm::ListingItem* item = document->currentItem();

    this->line("document_index", QString::number(document->itemIndex(item)));
    this->line("address", Convert::to_qstring(REDasm::String::hex(item->address())));
    this->line("type", this->itemType(item));
    this->line("index", QString::number(item->index()));

    this->line().header("DATA");

    // this->array("comments", item->data->comments.begin(), item->data->comments.end(),
    //             [&](const std::string& s) -> QString { return QString::fromStdString(s); });

    // this->array("auto_comments", item->data->autocomments.begin(), item->data->autocomments.end(),
    //             [&](const std::string& s) -> QString { return QString::fromStdString(s); });

    // this->line("meta", QString("{ name: \"%1\", type: \"%2\"}").arg(QString::fromStdString(item->data->meta.name),
    //                                                                 QString::fromStdString(item->data->meta.type)));

    // this->string("type", QString::fromStdString(item->data->type));
}

