#ifndef CHIP8_REGISTERS_H
#define CHIP8_REGISTERS_H

#define CHIP8_REG_V0_ID 0x0
#define CHIP8_REG_V1_ID 0x1
#define CHIP8_REG_V2_ID 0x2
#define CHIP8_REG_V3_ID 0x3
#define CHIP8_REG_V4_ID 0x4
#define CHIP8_REG_V5_ID 0x5
#define CHIP8_REG_V6_ID 0x6
#define CHIP8_REG_V7_ID 0x7
#define CHIP8_REG_V8_ID 0x8
#define CHIP8_REG_V9_ID 0x9
#define CHIP8_REG_VA_ID 0xA
#define CHIP8_REG_VB_ID 0xB
#define CHIP8_REG_VC_ID 0xC
#define CHIP8_REG_VD_ID 0xD
#define CHIP8_REG_VE_ID 0xE
#define CHIP8_REG_VF_ID 0xF

#define CHIP8_REG_I_ID  static_cast<register_t>('i')
#define CHIP8_REG_DT_ID static_cast<register_t>('d')
#define CHIP8_REG_ST_ID static_cast<register_t>('s')

#define CHIP8_REG_K   1
#define CHIP8_REG_I   2
#define CHIP8_REG_DT  3
#define CHIP8_REG_ST  4

#endif // CHIP8_REGISTERS_H
