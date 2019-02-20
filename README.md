<p align="center">
  <img src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artwork/logo_readme_20190204.png"/>
  <p align="center">
    <a href="https://travis-ci.org/REDasmOrg/REDasm">
      <img src="https://img.shields.io/travis/REDasmOrg/REDasm.svg?style=flat-square&logo=travis">
    </a>
    <a href="https://ci.appveyor.com/project/Dax89/redasm">
      <img src="https://img.shields.io/appveyor/ci/Dax89/redasm.svg?style=flat-square&logo=appveyor">
    </a>
    <a href="https://lgtm.com/projects/g/REDasmOrg/REDasm/context:cpp">
      <img alt="Language grade: C/C++" src="https://img.shields.io/lgtm/grade/cpp/g/REDasmOrg/REDasm.svg?logo=lgtm&logoWidth=18">
    </a>
    <img src="https://img.shields.io/badge/license-GPL3-8e725e.svg?style=flat-square">
    <a href="https://github.com/ellerbrock/open-source-badges/">
      <img src="https://badges.frapsoft.com/os/v1/open-source.png?v=103">
    </a>
  </p>
</p>

## Introduction
REDasm is an interactive, multiarchitecture disassembler written in modern C++11 using Qt5 as UI Framework.<br>
Its core is modular and it can be easily extended in order to support new [file formats](https://github.com/REDasmOrg/REDasm/wiki/Writing-a-FormatPlugin) and [instruction sets](https://github.com/REDasmOrg/REDasm/wiki/Writing-an-AssemblerPlugin).<br>
You can hack and improve REDasm without any issues and limitations.<br>
<br>
*Runs on Windows and Linux.*<br>

<p align="center">
  <img height="450" src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artwork/Slideshow_20190203.gif">
</p>

## Formats & Assemblers Support
<table>
  <tr> <!-- Loaders -->
    <td align="center" colspan="2"><b>Loaders</b></d>
  </tr>
  <tr>
    <td>Portable Executable</td>
    <td>32/64 bits</td>
  </tr>
  <tr>
    <td>ELF Executable</td>
    <td>32/64 bits, Little/Big endian</td>
  </tr>
  <tr>
    <td>Sony Playstation 1 Executable</td>
    <td>PsyQ 4.6/7 signatures available</td>
  </tr>
  <tr>
    <td>Android Dalvik Executable (DEX)</td>
    <td></td>
  </tr>
  <tr>
    <td>XBox1 Executable (XBE)</td>
    <td></td>
  </tr>
  <tr>
    <td>GameBoy Advance ROM</td>
     <td><i>In development</i></td>
  </tr>
  <tr>
    <td>Nintendo64 ROMS</td>
    <td>Little/Big endian and "swapped roms" are supported, <i>In development</i></td>
  </tr>
  <tr> <!-- Assemblers -->
    <td align="center" colspan="2"><b>Assemblers</b></d>
  </tr>
  <tr>
    <td>x86 and x86_64</td>
    <td>Capstone Based</td>
  </tr>
  <tr>
    <td>MIPS</td>
    <td>Capstone Based, Little/Big endian mode</td>
  </tr>
  <tr>
    <td>ARM</td>
    <td>Capstone Based, 32 bits only</td>
  </tr>
  <tr>
    <td>Dalvik</td>
    <td></td>
  </tr>
  <tr>
    <td>CHIP-8</td>
    <td>Just for Fun :)</td>
  </tr>
</table>

## Nightly Builds
* AppVeyor (Windows) and TravisCI (Linux) and they can be downloaded from [here](https://github.com/REDasmOrg/REDasm-Builds).

## Compiling from Source
See [COMPILE.md](COMPILE.md) (for Windows and Linux).

## Contributing
Read the [Wiki](https://github.com/REDasmOrg/REDasm/wiki) and send a Pull Request!

## Requirements
- CMake >= 3.10
- C++11 compiler (tested on GCC 6.x and MSVC2017)
- Qt >= 5.9 LTS

## Dependencies
- [Capstone](https://github.com/aquynh/capstone) : Capstone provides the most common architectures
- [JSON](https://github.com/nlohmann/json): A single header library for JSON
- [D3](https://github.com/d3/d3): Used by QtWebEngine for Graph Rendering
- [Dagre](https://github.com/dagrejs/dagre): Used for Graph Layout
- [Dagre-D3](https://github.com/dagrejs/dagre-d3): Graph Layout Rendering with D3
- [UndName](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/undname.c): MSVC Demangler
- [Visit-Struct](https://github.com/cbeck88/visit_struct): C++ Reflection

## License
REDasm is released under GNU GPL3 License.
