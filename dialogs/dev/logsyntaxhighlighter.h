#pragma once

#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QLinkedList>

class LogSyntaxHighlighter : public QSyntaxHighlighter
{
    Q_OBJECT

    private:
        struct Rule { QRegularExpression regex; QTextCharFormat format; };

    public:
        explicit LogSyntaxHighlighter(QTextDocument *parent);

    protected:
        void highlightBlock(const QString &text) override;

    private:
        void applyRule(const Rule& rule, const QString& text);

    private:
        QLinkedList<Rule> m_rules;
};
