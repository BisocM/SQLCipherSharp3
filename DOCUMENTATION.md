# SQLCipherSharp3 Documentation

## Overview
SQLCipherSharp3 encrypts and decrypts SQLite databases in a way that is compatible with SQLCipher 3.x. It uses AES-256-CBC encryption, PBKDF2 key derivation, per-page HMAC (SHA1), and defensive validation (constant-time HMAC comparison, config checks).

## Installation
- Package Manager: `Install-Package SQLCipherSharp3`
- .NET CLI: `dotnet add package SQLCipherSharp3`

## Quick Start
### Encrypt a database
```csharp
using System.IO;
using System.Text;
using SQLCipherSharp3;

byte[] plaintext = File.ReadAllBytes("path/to/database.sqlite");
byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

var encryptor = new SqlCipherEncryptor();
byte[] encryptedData = encryptor.Encrypt(plaintext, password);
File.WriteAllBytes("path/to/encrypted.db", encryptedData);
```

### Decrypt a database
```csharp
using System.IO;
using System.Text;
using SQLCipherSharp3;

byte[] encryptedData = File.ReadAllBytes("path/to/encrypted.db");
byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

var decryptor = new SqlCipherDecryptor();
byte[] decryptedData = decryptor.Decrypt(encryptedData, password);
File.WriteAllBytes("path/to/decrypted.sqlite", decryptedData);
```

### Asynchronous APIs
```csharp
using System.IO;
using System.Text;
using SQLCipherSharp3;

byte[] plaintext = await File.ReadAllBytesAsync("path/to/database.sqlite");
byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

var encryptor = new SqlCipherEncryptor();
byte[] encrypted = await encryptor.EncryptAsync(plaintext, password);

var decryptor = new SqlCipherDecryptor();
byte[] roundTripped = await decryptor.DecryptAsync(encrypted, password);
```

## Configuration
Create a `SqlCipherConfiguration` to override defaults:
```csharp
var config = new SqlCipherConfiguration
{
    PageSize = 1024,
    ReserveSize = 48,
    KeyIterations = 64000,
    HmacKeyIterations = 2
    // other fields available: SaltSize (16 fixed for SQLCipher 3), KeySize, HmacKeySize, IvSize, HmacSize, SaltMask
};

var encryptor = new SqlCipherEncryptor(config);
var decryptor = new SqlCipherDecryptor(config);
```
`Validate()` runs automatically in constructors and rejects invalid combinations (e.g., misaligned page sizes).

## Exceptions
- `WrongPasswordException`: HMAC verification failed (wrong password or corrupted ciphertext).
- `ArgumentException`: Null/empty inputs or malformed encrypted data/config.
- `InvalidDataException`: Unexpected data layout during decryption.

## Testing
`dotnet test SQLCipherSharp3.sln`

## Contributing
Pull requests are welcome. Please run tests before submitting. Issues/feature requests are tracked on GitHub.
