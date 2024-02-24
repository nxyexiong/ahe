# ahe
Average hacking enjoyer

# AhePkg usage
 - build AhePkg/AhePkg.dsc and get RootLoader.efi
 - rename it to bootx64.efi and place it into \EFI\BOOT\ under a FAT32 file system
 - build your driver (1. use custom entry point, 2. disable cfg)
 - rename it to payload.sys and place it beside bootx64.efi
 - boot from it

# how to setup edk2
- install vs2019 with VC++ development tools
- install nasm 2.16 from http://www.nasm.us to c:\nasm and add it to system environment variable 'PATH'
- install asl 20230628 from https://www.intel.com/content/www/us/en/developer/topic-technology/open/acpica/download.html to c:\asl
- install python 3.8.x
- create a working directory, for example, c:\workspace
- checkout edk2
 - cd c:\workspace
 - git clone -b edk2-stable202111 --recurse-submodules https://github.com/tianocore/edk2
- run test build
 - open Developer Command Prompt for VS2019
 - cd c:\workspace\edk2
 - edksetup.bat Rebuild
 - notepad Conf\target.txt
 - ACTIVE_PLATFORM       = MdeModulePkg/MdeModulePkg.dsc
 - TOOL_CHAIN_TAG        = VS2019
 - save
 - edksetup.bat
 - build -a X64 -t VS2019 -b NOOPT
- build helloworld
 - ...
 - build -a X64 -t VS2019 -b NOOPT -p ShellPkg\ShellPkg.dsc