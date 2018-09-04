#ifndef PE_RESOURCES_H
#define PE_RESOURCES_H

#include "pe_constants.h"
#include "pe_headers.h"

#define RESOURCE_PTR(t, resdir, offset) reinterpret_cast<t*>(reinterpret_cast<size_t>(resdir) + offset)

namespace REDasm {

class PEResources
{
    public:
        enum: u32 { CURSORS = 1, BITMAPS = 2, ICONS = 3, MENUS = 4, DIALOGS = 5,
                    STRING_TABLES = 6, FONT_DIRECTORY = 7, FONTS = 8, ACCELERATORS = 9,
                    RCDATA = 10, MESSAGE_TABLES = 11, CURSOR_GROUPS = 12, ICON_GROUPS = 14,
                    VERSION_INFO = 16, HTML_PAGES = 23, CONFIGURATION_FILES = 24 };

        typedef std::pair<ImageResourceDirectory*, ImageResourceDirectoryEntry*> ResourceItem;
        typedef std::function<offset_t(address_t)> RvaToOffsetCallback;

    public:
        PEResources(ImageResourceDirectory* resourcedirectory);
        ResourceItem find(u16 id) const;
        ResourceItem find(const std::string& name) const;
        ResourceItem find(u16 id, const ResourceItem& parentres) const;
        ResourceItem find(const std::string& name, const ResourceItem& parentres) const;

    public:
        template<typename T1, typename T2> T1* data(const PEResources::ResourceItem &item, T2 formatbase, RvaToOffsetCallback rtocb, u64* size = NULL) const;

    private:
        ResourceItem find(u16 id, ImageResourceDirectory* resourcedir) const;
        ResourceItem find(const std::string& name, ImageResourceDirectory* resourcedir) const;
        std::string entryName(ImageResourceDirectoryEntry* entry) const;
        std::string resourceid(u16 id) const;

    private:
        std::map<u16, std::string> m_resourcenames;
        ImageResourceDirectory* m_resourcedirectory;
};

template<typename T1, typename T2> T1* PEResources::data(const PEResources::ResourceItem &item, T2 formatbase, RvaToOffsetCallback rtocb, u64* size) const
{
    if(!item.second->DataIsDirectory)
    {
        if(!item.second->OffsetToData)
            return NULL;

        ImageResourceDataEntry* dataentry = RESOURCE_PTR(ImageResourceDataEntry, m_resourcedirectory, item.second->OffsetToData);

        if(size)
            *size = dataentry->Size;

        return reinterpret_cast<T1*>(reinterpret_cast<size_t>(formatbase) + rtocb(dataentry->OffsetToData));
    }

    ImageResourceDirectory* resourcedir = RESOURCE_PTR(ImageResourceDirectory, m_resourcedirectory, item.second->OffsetToDirectory);
    size_t c = resourcedir->NumberOfIdEntries + resourcedir->NumberOfNamedEntries;

    if(c != 1)
        return NULL;

    ImageResourceDirectoryEntry* entry = reinterpret_cast<ImageResourceDirectoryEntry*>(resourcedir + 1);
    return this->data<T1, T2>(std::make_pair(resourcedir, entry), formatbase, rtocb, size);
}

} // namespace REDasm

#endif // PE_RESOURCES_H
