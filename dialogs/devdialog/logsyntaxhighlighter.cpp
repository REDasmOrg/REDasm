#include "logsyntaxhighlighter.h"
#include "../../themeprovider.h"

#define RULE_NAME(name) r_##name

#define CREATE_RULE(name, r, f) Rule RULE_NAME(name); \
                                RULE_NAME(name).regex = QRegularExpression(r); \
                                RULE_NAME(name).format.setForeground(THEME_VALUE(f)); \
                                m_rules.push_back(RULE_NAME(name));

LogSyntaxHighlighter::LogSyntaxHighlighter(QTextDocument *parent) : QSyntaxHighlighter(parent)
{
    CREATE_RULE(hexdigits, "\\b[0-9a-fA-F]+\\b", "immediate_fg");
    CREATE_RULE(strings, "\"[^\"]*\"", "string_fg");
}

void LogSyntaxHighlighter::highlightBlock(const QString &text)
{
    for(auto it = m_rules.begin(); it != m_rules.end(); it++)
        this->applyRule(*it, text);
}

void LogSyntaxHighlighter::applyRule(const LogSyntaxHighlighter::Rule &rule, const QString &text)
{
    auto it = rule.regex.globalMatch(text);

    while(it.hasNext())
    {
        auto m = it.next();
        this->setFormat(m.capturedStart(), m.capturedLength(), rule.format);
    }
}
