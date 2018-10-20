#ifndef PE_DEBUG_H
#define PE_DEBUG_H

#include "../../redasm.h"
#include "pe_common.h"

#define PE_PDB_NB10_SIGNATURE 0x3031424E // 01BN
#define PE_PDB_RSDS_SIGNATURE 0x53445352 // SDSR

namespace REDasm {

struct CVHeader { u32 Signature, Offset; };

struct CvInfoPDB20
{
    CVHeader CvHeader;
    u32 Signature, Age;
    char PdbFileName[1];
};

struct CvInfoPDB70
{
    u32 CvSignature;
    GUID Signature;
    u32 Age;
    char PdbFileName[1];
};

} // namespace REDasm

#endif // PE_DEBUG_H
