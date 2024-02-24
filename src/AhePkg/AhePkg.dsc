[Defines]
    PLATFORM_NAME                  = Ahe
    PLATFORM_GUID                  = 9CA16C29-A35B-4D16-B1A1-C152EBBCAC23
    PLATFORM_VERSION               = 1.00
    DSC_SPECIFICATION              = 0x0001001B
    OUTPUT_DIRECTORY               = Build/Ahe
    SUPPORTED_ARCHITECTURES        = X64
    BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
    SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
    # entry point
    UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
    # basic
    BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
    PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
    BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
    # uefi
    UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
    UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
    UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
    PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
    MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
    # misc
    DevicePathLib|MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
!if $(TARGET) == RELEASE
    DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
    !ifdef $(DEBUG_ON_SERIAL_PORT)
        DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
    !else
        DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
    !endif
!endif
    DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
    RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[Components]
    AhePkg/Application/RootLoader/RootLoader.inf
