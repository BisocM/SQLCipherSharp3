[![NuGet version (SQLCipherSharp3)](https://img.shields.io/nuget/v/SQLCipherSharp3.svg?style=flat-square)](https://www.nuget.org/packages/SQLCipherSharp3)

# SQLCipherSharp3

SQLCipherSharp3 is a robust .NET library that enables encryption and decryption of SQLite databases in a manner compatible with SQLCipher 3.x. The library leverages industry-standard cryptographic techniques—including AES-CBC encryption, PBKDF2 key derivation, and HMAC verification—to secure your data while ensuring its integrity.

## Features

- **SQLCipher 3.x Compatibility:** Encrypt and decrypt SQLite databases using methods compatible with SQLCipher 3.x.
- **AES-CBC Encryption:** Secure your data with 256-bit AES encryption in CBC mode.
- **PBKDF2 Key Derivation:** Generate cryptographic keys using customizable PBKDF2 parameters.
- **HMAC Verification:** Maintain data integrity with HMAC using SHA1.
- **Customizable Configuration:** Easily modify file layout and cryptographic parameters via an instance-based configuration class.
- **Synchronous & Asynchronous Operations:** Support for both blocking and non-blocking API calls to suit various application needs.
- **Simple Integration:** Seamlessly incorporate SQLCipherSharp3 into your .NET applications.

## Installation

SQLCipherSharp3 is available as a NuGet package. Install it using the Package Manager Console:

```powershell
Install-Package SQLCipherSharp3
```

Or add it directly to your project file:

```xml
<PackageReference Include="SQLCipherSharp3" Version="1.0.0" />
```

## Getting Started

### Encrypting a SQLite Database

Below is an example of how to encrypt a SQLite database:

```csharp
using System;
using System.IO;
using System.Text;
using SQLCipherSharp3;

class Program
{
    static void Main()
    {
        // Load your plaintext SQLite database
        byte[] plaintext = File.ReadAllBytes("path/to/your/database.sqlite");
        byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

        // Optionally create a custom configuration
        var config = new SqlCipherConfiguration
        {
            PageSize = 1024,
            KeyIterations = 64000,
            // ... set additional custom parameters as needed
        };

        // Create an encryptor instance with the configuration (or omit config to use defaults)
        var encryptor = new SqlCipherEncryptor(config);
        byte[] encryptedData = encryptor.Encrypt(plaintext, password);

        // Save the encrypted database
        File.WriteAllBytes("path/to/your/encrypted.db", encryptedData);
    }
}
```

### Decrypting a SQLite Database

Here’s how to decrypt a previously encrypted SQLite database:

```csharp
using System;
using System.IO;
using System.Text;
using SQLCipherSharp3;

class Program
{
    static void Main()
    {
        // Load your encrypted database
        byte[] encryptedData = File.ReadAllBytes("path/to/your/encrypted.db");
        byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

        // Create a decryptor instance (using the same configuration as encryption)
        var decryptor = new SqlCipherDecryptor();
        byte[] decryptedData = decryptor.Decrypt(encryptedData, password);

        // Save the decrypted database
        File.WriteAllBytes("path/to/your/decrypted.sqlite", decryptedData);
    }
}
```

### Asynchronous Usage

Both encryption and decryption methods are available asynchronously:

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using SQLCipherSharp3;

class Program
{
    static async Task Main()
    {
        byte[] encryptedData = await File.ReadAllBytesAsync("path/to/your/encrypted.db");
        byte[] password = Encoding.UTF8.GetBytes("your-secret-password");

        var decryptor = new SqlCipherDecryptor();
        byte[] decryptedData = await decryptor.DecryptAsync(encryptedData, password);

        await File.WriteAllBytesAsync("path/to/your/decrypted.sqlite", decryptedData);
    }
}
```

## Customizing Configuration

The `SqlCipherConfiguration` class allows you to modify all underlying parameters, such as page size, key sizes, iteration counts, and more. For example:

```csharp
var config = new SqlCipherConfiguration
{
    SaltSize = 16,
    PageSize = 2048,
    ReserveSize = 48,
    KeySize = 32,
    KeyIterations = 100000,
    HmacKeySize = 32,
    HmacKeyIterations = 2,
    IvSize = 16,
    HmacSize = 20,
    SaltMask = 0x3A
};

var encryptor = new SqlCipherEncryptor(config);
var decryptor = new SqlCipherDecryptor(config);
```

## Unit Tests

SQLCipherSharp3 includes a comprehensive suite of unit tests covering:
- Synchronous and asynchronous decryption
- Handling invalid passwords
- Validation of input data

See the `SQLCipherSharp3.Tests` project for detailed test cases.

## Contributing

Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request. Make sure to run the tests before submitting your changes.