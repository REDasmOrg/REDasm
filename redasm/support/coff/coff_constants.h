#ifndef COFF_CONSTANTS_H
#define COFF_CONSTANTS_H

#define E_SYMNMLEN  8   // Number of characters in a symbol name
#define E_FILNMLEN 14   // Number of characters in a file name
#define E_DIMNUM    4   // Number of array dimensions in auxiliary entry

#define C_NULL      0   // No entry
#define C_AUTO      1   // Automatic variable
#define C_EXT       2   // External (public) symbol - this covers globals and externs
#define C_STAT      3   // static (private) symbol
#define C_REG       4   // register variable
#define C_EXTDEF    5   // External definition
#define C_LABEL     6   // label
#define C_ULABEL    7   // undefined label
#define C_MOS       8   // member of structure
#define C_ARG       9   // function argument
#define C_STRTAG    10  // structure tag
#define C_MOU       11  // member of union
#define C_UNTAG     12  // union tag
#define C_TPDEF     13  // type definition
#define C_USTATIC   14  // undefined static
#define C_ENTAG     15  // enumeration tag
#define C_MOE       16  // member of enumeration
#define C_REGPARM   17  // register parameter
#define C_FIELD     18  // bit field
#define C_AUTOARG   19  // auto argument
#define C_LASTENT   20  // dummy entry (end of block)
#define C_BLOCK     100 // ".bb" or ".eb" - beginning or end of block
#define C_FCN       101 // ".bf" or ".ef" - beginning or end of function
#define C_EOS       102 // end of structure
#define C_FILE      103 // file name
#define C_LINE      104 // line number, reformatted as symbol
#define C_ALIAS     105 // duplicate tag
#define C_HIDDEN    106 // ext symbol in dmert public lib
#define C_EFCN      255 // physical end of function

#endif // COFF_CONSTANTS_H
