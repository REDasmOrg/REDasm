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
        REDasm::ListingItem* block = doc->at(i);

        if(this->isBlockRendered(i, block))
            continue;

        QTextBlock textblock = m_textdocument->findBlockByLineNumber(i);

        if(!textblock.isValid())
        {
            textcursor = QTextCursor(m_textdocument);
            textcursor.movePosition(QTextCursor::End);
        }
        else
            textcursor = QTextCursor(textblock);

        this->insertBlock(textcursor, block);
    }
}

bool DisassemblerTextDocument::isBlockRendered(size_t line, REDasm::ListingItem *block)
{
    QTextBlock textblock = m_textdocument->findBlockByLineNumber(line);
    QTextBlockFormat blockformat = textblock.blockFormat();
    REDasm::ListingItem* lineblock = reinterpret_cast<REDasm::ListingItem*>(blockformat.property(DisassemblerDocument::Block).value<void*>());
    return lineblock == block;
}

void DisassemblerTextDocument::insertBlock(QTextCursor& textcursor, REDasm::ListingItem *block)
{
    if(textcursor.block().blockFormat().hasProperty(DisassemblerDocument::Block))
        textcursor.insertBlock();

    QTextBlockFormat blockformat;
    blockformat.setProperty(DisassemblerDocument::Address, QVariant::fromValue(block->address));
    blockformat.setProperty(DisassemblerDocument::Block, QVariant::fromValue(reinterpret_cast<void*>(block)));
    textcursor.setBlockFormat(blockformat);

    if(block->is(REDasm::ListingItem::SegmentItem))
        this->insertSegment(textcursor, block);
    else if(block->is(REDasm::ListingItem::FunctionItem))
        this->insertFunction(textcursor, block);
    else if(block->is(REDasm::ListingItem::InstructionItem))
        this->insertInstruction(textcursor, block);
    else
        Q_ASSERT(false);
}

void DisassemblerTextDocument::insertSegment(QTextCursor& textcursor, REDasm::ListingItem *block)
{
    REDasm::Segment* segment = m_disassembler->document()->segment(block->address);

    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("segment_fg"));

    textcursor.setBlockCharFormat(charformat);
    textcursor.insertText(QString("segment '%1' start: %2 end %3").arg(segment ? S_TO_QS(segment->name) : "???")
                                                                  .arg(HEX_ADDRESS(segment->address))
                                                                  .arg(HEX_ADDRESS(segment->endaddress)));
}

void DisassemblerTextDocument::insertFunction(QTextCursor& textcursor, REDasm::ListingItem *block)
{
    QTextCharFormat charformat;
    charformat.setForeground(THEME_VALUE("function_fg"));
    textcursor.setBlockCharFormat(charformat);

    m_printer->function(m_disassembler->document()->symbol(block->address), [this, &textcursor](const std::string& pre, const std::string& sym, const std::string& post) {
        if(!pre.empty())
            textcursor.insertText(S_TO_QS(pre));

        textcursor.insertText(S_TO_QS(sym));

        if(!post.empty())
            textcursor.insertText(S_TO_QS(post));
    });
}

void DisassemblerTextDocument::insertInstruction(QTextCursor &textcursor, REDasm::ListingItem *block)
{

}
