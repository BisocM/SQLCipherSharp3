[![NuGet version (SQLCipherSharp3)](https://img.shields.io/nuget/v/SQLCipherSharp3.svg?style=flat-square)](https://www.nuget.org/packages/SQLCipherSharp3)

# SQLCipherSharp3

.NET library for SQLCipher 3.x–compatible SQLite encryption/decryption with hardened defaults, constant-time HMAC validation, and sync/async APIs.

## Features
- AES-256-CBC with PBKDF2 key derivation and per-page HMAC (SHA1) matching SQLCipher 3.x.
- Constant-time HMAC verification and defensive config/input validation.
- Sync and async APIs; configurable page/reserve sizes; ships with safe defaults.

## Quick Start
```csharp
using System.IO;
using System.Text;
using SQLCipherSharp3;

byte[] db = File.ReadAllBytes("db.sqlite");
byte[] pwd = Encoding.UTF8.GetBytes("secret");

var encryptor = new SqlCipherEncryptor();
byte[] enc = encryptor.Encrypt(db, pwd);

var decryptor = new SqlCipherDecryptor();
byte[] dec = decryptor.Decrypt(enc, pwd);
```

Install: `dotnet add package SQLCipherSharp3` (version 2.0.0, net8.0).

Full usage, configuration, and contribution details: see `DOCUMENTATION.md`.
