#include "disassemblertextdocument.h"
#include <algorithm>
#include <QDebug>

DisassemblerTextDocument::DisassemblerTextDocument(REDasm::Disassembler *disassembler, QTextDocument *document, QObject *parent): DisassemblerDocument(disassembler, document, parent)
{
    REDasm::ListingDocument* doc = disassembler->format()->document();
    doc->sort();
}

void DisassemblerTextDocument::displayRange(size_t start, size_t count)
{
    REDasm::ListingDocument* doc = m_disassembler->format()->document();
    QTextCursor textcursor;

    for(size_t i = start; i < std::min(doc->count(), start + count); i++)
    {
        REDasm::ListingItem* item = doc->at(i);

        if(this->isItemRendered(i, item))
            continue;

        QTextBlock textblock = m_textdocument->findBlockByLineNumber(i);

        if(textblock.isValid())
            textblock = textblock.previous();

        if(!textblock.isValid())
        {
            textcursor = QTextCursor(m_textdocument);
            textcursor.movePosition(QTextCursor::End);
        }
        else
        {
            textcursor = QTextCursor(textblock);
            textcursor.movePosition(QTextCursor::EndOfBlock);
        }

        this->insertItem(textcursor, item);
    }
}

bool DisassemblerTextDocument::isItemRendered(size_t line, REDasm::ListingItem *item)
{
    QTextBlock textblock = m_textdocument->findBlockByLineNumber(line);
    QTextBlockFormat blockformat = textblock.blockFormat();
    REDasm::ListingItem* lineitem = reinterpret_cast<REDasm::ListingItem*>(blockformat.property(DisassemblerDocument::Item).value<void*>());
    return lineitem == item;
}

void DisassemblerTextDocument::insertItem(QTextCursor& textcursor, REDasm::ListingItem *item)
{
    if(textcursor.block().blockFormat().hasProperty(DisassemblerDocument::Item))
        textcursor.insertBlock();

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(item->address));
    blockformat.setProperty(DisassemblerDocument::Item, QVariant::fromValue(reinterpret_cast<void*>(item)));
    textcursor.setBlockFormat(blockformat);

    if(item->is(REDasm::ListingItem::SegmentItem))
        this->insertSegmentItem(textcursor, item);
    else if(item->is(REDasm::ListingItem::FunctionItem))
        this->insertFunctionItem(textcursor, item);
    else if(item->is(REDasm::ListingItem::InstructionItem))
        this->insertInstructionItem(textcursor, item);
    else
        Q_ASSERT(false);
}

void DisassemblerTextDocument::insertSegmentItem(QTextCursor& textcursor, REDasm::ListingItem *item)
{
    REDasm::Segment* segment = m_disassembler->document()->segment(item->address);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("segment_fg"));

    textcursor.setBlockCharFormat(charformat);
    textcursor.insertText(QString("segment '%1' start: %2 end %3").arg(segment ? S_TO_QS(segment->name) : "???")
                                                                  .arg(HEX_ADDRESS(segment->address))
                                                                  .arg(HEX_ADDRESS(segment->endaddress)));
}

void DisassemblerTextDocument::insertFunctionItem(QTextCursor& textcursor, REDasm::ListingItem *item)
{
    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("function_fg"));
    textcursor.setBlockCharFormat(charformat);

    this->insertIndent(textcursor, item->address, 1);

    m_printer->function(m_disassembler->document()->symbol(item->address), [this, &textcursor](const std::string& pre, const std::string& sym, const std::string& post) {
        if(!pre.empty())
            textcursor.insertText(S_TO_QS(pre));

        textcursor.insertText(S_TO_QS(sym));

        if(!post.empty())
            textcursor.insertText(S_TO_QS(post));
    });
}

void DisassemblerTextDocument::insertInstructionItem(QTextCursor &textcursor, REDasm::ListingItem *item)
{
    REDasm::InstructionPtr instruction = m_disassembler->document()->instruction(item->address);

    QTextCharFormat charformat;
    textcursor.setBlockCharFormat(charformat);

    this->insertInstruction(textcursor, instruction);
}
