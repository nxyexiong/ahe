# ahe
Average hacking enjoyer

# mapper usage
 - build mapper (and caproot if you want to map a driver)
 - run it without parameters to checkout usage

# AhePkg usage
 - build AhePkg/AhePkg.dsc and get RootLoader.efi
 - rename it to bootx64.efi and place it into \EFI\BOOT\ under a FAT32 file system
 - build your driver (1. use custom entry point, 2. disable cfg, 3. add unhook exports and unhook on startup), in this project just compile and use bootdrv
 - rename the driver to payload.sys and place it beside bootx64.efi
 - boot from it

# how to setup edk2
- install vs2019 with VC++ development tools
- install nasm 2.16 from http://www.nasm.us to c:\nasm and add it to system environment variable 'PATH'
- install asl 20230628 from https://www.intel.com/content/www/us/en/developer/topic-technology/open/acpica/download.html to c:\asl
- install python 3.8.x
- create a working directory, for example, c:\workspace
- checkout edk2
```
 - cd c:\workspace
 - git clone -b edk2-stable202111 --recurse-submodules https://github.com/tianocore/edk2
```
- run test build
```
 - open Developer Command Prompt for VS2019
 - cd c:\workspace\edk2
 - edksetup.bat Rebuild
 - notepad Conf\target.txt
 - ACTIVE_PLATFORM       = MdeModulePkg/MdeModulePkg.dsc
 - TOOL_CHAIN_TAG        = VS2019
 - save
 - edksetup.bat
 - build -a X64 -t VS2019 -b NOOPT
```
- build AhePkg
```
 - copy AhePkg to edk2 directory
 - build -a X64 -t VS2019 -b NOOPT -p AhePkg\AhePkg.dsc
```

# how to bypass secure boot
 - download original .cap BIOS firmware
 - open it with [UefiTool](https://github.com/LongSoft/UEFITool) (dont use the NE ones as they cannot replace binaries)
 - find the image verification module, you can do it by text searching "image verification"
 - right click on it and select extract body
 - reverse engineer it, find the function that verifies the image, you can find it by searching immediate value 0x800000000000001A (EFI_SECURITY_VIOLATION)
 - patch the function, make it returns 0 (for example 48 31 C0 C3 for xor rax, rax; retn;)
 - in UefiTool, right click on the image and select replace body to replace it with the patched one
 - save the .cap
 - flash it and youre done (for asus mbs that have USB BIOS FlashBack, you can simply just place it into a FAT32 usb drive and insert it into the port and flash, but for other mbs you have to find other ways around)

# credits
 - [drvmap](https://github.com/not-wlan/drvmap)
 - [umap](https://github.com/btbd/umap)
 - [PatchBoot](https://github.com/SamuelTulach/PatchBoot)
