#ifndef PE_H
#define PE_H

#include "../../plugins/plugins.h"
#include "pe_headers.h"
#include "pe_resources.h"
#include "pe_imports.h"
#include "pe_utils.h"
#include "dotnet/dotnet_header.h"
#include "dotnet/dotnet_reader.h"

#define RVA_POINTER(type, rva)        (pointer<type>(rvaToOffset(rva)))
#define RVA_POINTER_OK(type, rva, ok) (pointer<type>(rvaToOffset(rva, ok)))

namespace REDasm {

class PeFormat: public FormatPluginT<ImageDosHeader>
{
    private:
        enum PeType { None, DotNet, VisualBasic, Delphi, TurboCpp };

    public:
        PeFormat(Buffer& buffer);
        virtual ~PeFormat();
        virtual const char* name() const;
        virtual u32 bits() const;
        virtual const char* assembler() const;
        virtual Analyzer* createAnalyzer(DisassemblerAPI *disassembler, const SignatureFiles &signatures) const;
        virtual bool load();
        const DotNetReader *dotNetReader() const;

    private:
        u64 rvaToOffset(u64 rva, bool *ok = NULL) const;
        void checkDelphi(const REDasm::PEResources &peresources);
        void checkResources();
        void checkDebugInfo();
        ImageCorHeader *checkDotNet();
        void loadDotNet(ImageCor20Header* corheader);
        void loadDefault();
        void loadSections();
        void loadExports();
        void loadImports();
        void loadSymbolTable();

    private:
        template<typename THUNK, u64 ordinalflag> void readDescriptor(const ImageImportDescriptor& importdescriptor);

    private:
        DotNetReader* m_dotnetreader;
        ImageDosHeader* m_dosheader;
        ImageNtHeaders* m_ntheaders;
        ImageSectionHeader* m_sectiontable;
        ImageDataDirectory* m_datadirectory;
        u64 m_petype, m_imagebase, m_sectionalignment, m_entrypoint;
};

template<typename THUNK, u64 ordinalflag> void PeFormat::readDescriptor(const ImageImportDescriptor& importdescriptor)
{
    // Check if OFT exists
    THUNK* thunk = RVA_POINTER(THUNK, importdescriptor.OriginalFirstThunk ? importdescriptor.OriginalFirstThunk :
                                                                            importdescriptor.FirstThunk);

    std::string descriptorname = RVA_POINTER(const char, importdescriptor.Name);
    std::transform(descriptorname.begin(), descriptorname.end(), descriptorname.begin(), ::tolower);

    if(descriptorname.find("msvbvm") != std::string::npos)
        this->m_petype = PeType::VisualBasic;

    for(size_t i = 0; thunk[i]; i++)
    {
        std::string importname;
        address_t address = m_imagebase + (importdescriptor.FirstThunk + (i * sizeof(THUNK))); // Instructions refers to FT

        if(!(thunk[i] & ordinalflag))
        {
            bool ok = false;
            ImageImportByName* importbyname = RVA_POINTER_OK(ImageImportByName, thunk[i], &ok);

            if(!ok)
                continue;

            importname = PEUtils::importName(descriptorname, reinterpret_cast<const char*>(&importbyname->Name));
        }
        else
        {
            u16 ordinal = static_cast<u16>(ordinalflag ^ thunk[i]);

            if(!PEImports::importName(descriptorname, ordinal, importname))
                importname = PEUtils::importName(descriptorname, ordinal);
            else
                importname = PEUtils::importName(descriptorname, importname);
        }

        m_document.lock(address, importname, SymbolTypes::Import);
    }
}

DECLARE_FORMAT_PLUGIN(PeFormat, pe)

}

#endif // PE_H
