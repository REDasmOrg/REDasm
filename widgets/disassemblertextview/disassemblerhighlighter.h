#ifndef DISASSEMBLERHIGHLIGHTER_H
#define DISASSEMBLERHIGHLIGHTER_H

#include <QSyntaxHighlighter>
#include "../../redasm/redasm.h"
#include <QRegularExpression>

class DisassemblerHighlighter : public QSyntaxHighlighter
{
    Q_OBJECT

    public:
        explicit DisassemblerHighlighter(QTextDocument *document = nullptr);
        void setHighlightColor(const QColor& color);
        void setSeekColor(const QColor& color);
        void highlight(const QString& word, const QString& currentaddress, const QTextBlock &block);

    protected:
        virtual void highlightBlock(const QString &text);

    private:
        void highlightWords(const QString& text);
        void highlightSeek(const QString& text);

    private:
        QRegularExpression _rgxaddress;
        QColor _highlightcolor, _seekcolor;
        QString _word;
};

#endif // DISASSEMBLERHIGHLIGHTER_H
