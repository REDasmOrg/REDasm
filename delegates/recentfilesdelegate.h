#pragma once

#include <QStyledItemDelegate>
#include <QFileInfo>

class RecentFilesDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    public:
        RecentFilesDelegate(QObject* parent);
        void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
        QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    private:
        void drawIcon(QPainter *painter, const QStyleOptionViewItem& option) const;
        void drawFileName(QPainter *painter, const QFileInfo& fi, const QStyleOptionViewItem& option) const;
        void drawFilePath(QPainter *painter, const QFileInfo& fi, const QStyleOptionViewItem& option, const QModelIndex& index) const;
};

