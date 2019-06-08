#ifndef SIGNATUREFILESMODEL_H
#define SIGNATUREFILESMODEL_H

#include <QAbstractListModel>
#include <redasm/disassembler/disassembler.h>
#include <redasm/database/signaturedb.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/libs/json/json.hpp>

class SignatureFilesModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit SignatureFilesModel(REDasm::Disassembler* disassembler, QObject *parent = nullptr);
        const REDasm::SignatureDB* load(const QModelIndex& index);
        const std::string& signatureId(const QModelIndex& index) const;
        const std::string& signaturePath(const QModelIndex& index) const;
        bool isLoaded(const QModelIndex& index) const;
        bool contains(const std::string& sigid) const;
        void add(const std::string& sigid, const std::string& sigpath);
        void mark(const QModelIndex& index);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;

    private:
        QList< QPair<std::string, std::string> > m_signaturefiles;
        QHash<int, REDasm::SignatureDB> m_loadedsignatures;
        REDasm::Disassembler* m_disassembler;
};

#endif // SIGNATUREFILESMODEL_H
