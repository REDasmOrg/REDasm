#include "pe_resources.h"

#define ADD_RESOURCE_ID(id) m_resourcenames[PEResources::id] = #id
#define NULL_RESOURCE std::make_pair<ImageResourceDirectory*, ImageResourceDirectoryEntry*>(NULL, NULL)

namespace REDasm {

PEResources::PEResources(ImageResourceDirectory *resourcedirectory): m_resourcedirectory(resourcedirectory)
{
    ADD_RESOURCE_ID(CURSORS);
    ADD_RESOURCE_ID(BITMAPS);
    ADD_RESOURCE_ID(ICONS);
    ADD_RESOURCE_ID(MENUS);
    ADD_RESOURCE_ID(DIALOGS);
    ADD_RESOURCE_ID(STRING_TABLES);
    ADD_RESOURCE_ID(FONT_DIRECTORY);
    ADD_RESOURCE_ID(FONTS);
    ADD_RESOURCE_ID(ACCELERATORS);
    ADD_RESOURCE_ID(RCDATA);
    ADD_RESOURCE_ID(MESSAGE_TABLES);
    ADD_RESOURCE_ID(CURSOR_GROUPS);
    ADD_RESOURCE_ID(ICON_GROUPS);
    ADD_RESOURCE_ID(VERSION_INFO);
    ADD_RESOURCE_ID(HTML_PAGES);
    ADD_RESOURCE_ID(CONFIGURATION_FILES);
}

PEResources::ResourceItem PEResources::find(u16 id) const { return this->find(id, m_resourcedirectory); }
PEResources::ResourceItem PEResources::find(const std::string &name) const { return this->find(name, m_resourcedirectory); }
PEResources::ResourceItem PEResources::find(u16 id, const PEResources::ResourceItem &parentres) const { return this->find(this->resourceid(id), parentres); }

PEResources::ResourceItem PEResources::find(const std::string &name, const PEResources::ResourceItem &parentres) const
{
    if(!parentres.second->DataIsDirectory)
        return NULL_RESOURCE;

    ImageResourceDirectory* resourcedir = RESOURCE_PTR(ImageResourceDirectory, parentres.first,
                                                       parentres.second->OffsetToDirectory);

    return this->find(name, resourcedir);
}

PEResources::ResourceItem PEResources::find(u16 id, ImageResourceDirectory *resourcedir) const
{
    return this->find(this->resourceid(id), resourcedir);
}

PEResources::ResourceItem PEResources::find(const std::string &name, ImageResourceDirectory *resourcedir) const
{
    u32 c = resourcedir->NumberOfIdEntries + resourcedir->NumberOfNamedEntries;
    ImageResourceDirectoryEntry* entries = reinterpret_cast<ImageResourceDirectoryEntry*>(resourcedir + 1);

    for(u32 i = 0; i < c; i++)
    {
        std::string n = this->entryName(&entries[i]);

        if(name == n)
            return std::make_pair(resourcedir, &entries[i]);
    }

    return NULL_RESOURCE;
}

std::string PEResources::entryName(ImageResourceDirectoryEntry *entry) const
{
    if(entry->NameIsString)
    {
        ImageResourceDirStringU* name = RESOURCE_PTR(ImageResourceDirStringU, m_resourcedirectory, entry->NameOffset);
        return REDasm::wtoa(&name->NameString, name->Length);
    }

    return this->resourceid(entry->Id);
}

std::string PEResources::resourceid(u16 id) const
{
    auto it = m_resourcenames.find(id);

    if(it == m_resourcenames.end())
        return "#" + std::to_string(id);

    return it->second;
}

}
