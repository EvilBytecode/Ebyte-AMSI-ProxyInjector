# EByte-AMSI-ProxyInjector

An "innovative" AMSI bypass tool that uses function redirection with NT* API calls.

## Features

- Thread-safe implementation with proper thread suspension/resumption
- Verbose debugging mode for detailed operation analysis
- Minimal dependencies - uses only core Windows APIs

## How It Works

The tool employs a function redirection approach instead of direct byte patching:

1. **Targeting**: Accepts a process ID (PID) as input to target a specific process

2. **Thread Management**: 
   - Suspends all threads in the target process to prevent race conditions
   - Uses `NtSuspendThread` and `NtResumeThread` for atomic operations

3. **AMSI Detection**: 
   - Locates `amsi.dll` in the target process
   - Calculates the offset of `AmsiScanBuffer` from the module base
   - Maps this offset to find the function in the target process

4. **Redirection Implementation**:
   - Allocates memory in the target process for a proxy function
   - Writes a minimal assembly function that preserves register state but always returns 0 (clean)
   - Creates a jump instruction at the start of the original `AmsiScanBuffer` function
   - Redirects execution to the clean proxy function

5. **Cleanup**:
   - Resumes all previously suspended threads
   - Properly closes all handles to prevent resource leaks

## Technical Details

### Memory Manipulation

The tool uses the following NT API calls for memory operations:
- `NtAllocateVirtualMemory`: Allocates memory for the proxy function
- `NtProtectVirtualMemory`: Changes memory protection to allow writing/execution
- `NtWriteVirtualMemory`: Writes the proxy function and jump instruction

### Proxy Function Implementation

The proxy function is a small assembly routine that:
1. Preserves register state by saving registers to the stack
2. Sets EAX to 0 (representing AMSI_RESULT_CLEAN)
3. Restores register state
4. Returns to the caller

```assembly
mov [rsp+8], rbx      ; Save registers
mov [rsp+10h], rsi
push rdi
sub rsp, 20h
xor eax, eax          ; Set return value to 0 (AMSI_RESULT_CLEAN)
add rsp, 20h          ; Restore stack
pop rdi               ; Restore registers
mov rsi, [rsp+10h]
mov rbx, [rsp+8]
ret                   ; Return to caller
```

### Function Redirection

The redirection is implemented by writing a jump instruction at the beginning of the `AmsiScanBuffer` function:

```assembly
mov rax, [proxy_address]  ; Load proxy function address
jmp rax                   ; Jump to proxy
```

This ensures that any call to AMSI's scanning function will be redirected to our proxy, which always returns "clean".

## Usage

```
EByte-Pattern-AmsiPatch.exe <PID> [options]

Options:
  -v, --verbose    Enable verbose debugging output
  -h, --help       Display this help message

Example:
  EByte-Pattern-AmsiPatch.exe 1234 --verbose
```

## PoC:
![image](https://github.com/user-attachments/assets/d52514bd-e29c-4808-8631-b1f578de1282)
![image_2025-05-15_15-26-10](https://github.com/user-attachments/assets/f379c2cb-dfc9-42e6-8007-690a0115ce0e)
![image](https://github.com/user-attachments/assets/3c724a78-b018-45ab-a807-e85c02a07f54)


## Disclaimer

This tool is provided for educational and research purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## License

This project is available under the MIT License. See the LICENSE file for details. 
