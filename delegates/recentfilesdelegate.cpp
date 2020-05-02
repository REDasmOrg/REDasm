#include "recentfilesdelegate.h"
#include "../themeprovider.h"
#include "../redasmfonts.h"
#include <QApplication>
#include <QPainter>
#include <QIcon>

RecentFilesDelegate::RecentFilesDelegate(QObject* parent): QStyledItemDelegate(parent) { }

void RecentFilesDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    QStyleOptionViewItem newoption = option;
    newoption.rect.adjust(4, 4, -4, -4);
    painter->save();

    if(option.state & QStyle::State_MouseOver)
    {
        if(ThemeProvider::isDarkTheme()) painter->fillRect(option.rect, option.palette.window().color().lighter(115));
        else painter->fillRect(option.rect, option.palette.window().color().darker(115));
    }

    QString filepath = index.data(Qt::UserRole).toString();
    QFileInfo fi(filepath);

    this->drawIcon(painter, newoption);
    this->drawFileName(painter, fi, newoption);
    this->drawFilePath(painter, fi, newoption, index);
    painter->restore();
}

QSize RecentFilesDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    QSize sz = QStyledItemDelegate::sizeHint(option, index);
    sz.rheight() *= 3;
    return sz;
}

void RecentFilesDelegate::drawIcon(QPainter* painter, const QStyleOptionViewItem& option) const
{
    QRect r = option.rect;
    r.setWidth(option.fontMetrics.height());
    r.setHeight(option.fontMetrics.height());

    FA_ICON(0xf1ce).paint(painter, r, Qt::AlignVCenter);
}

void RecentFilesDelegate::drawFileName(QPainter* painter, const QFileInfo& fi, const QStyleOptionViewItem& option) const
{
    QFont oldfont = painter->font(), currfont(painter->font());
    currfont.setBold(true);

    if(option.state & QStyle::State_MouseOver)
        currfont.setUnderline(true);

    QRect r = option.rect;
    r.setLeft(option.fontMetrics.height() * 2);

    painter->setFont(currfont);
    painter->drawText(r, Qt::AlignLeft | Qt::AlignTop, fi.baseName());
    painter->setFont(oldfont);
}

void RecentFilesDelegate::drawFilePath(QPainter* painter, const QFileInfo& fi, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    QRect r = option.rect;
    r.setLeft(option.fontMetrics.height() * 2);
    r.setY(r.y() + QStyledItemDelegate::sizeHint(option, index).height());

    painter->drawText(r, Qt::AlignLeft | Qt::AlignTop, fi.filePath());
}
