using System.Security.Cryptography;

namespace SQLCipherSharp3;

/// <summary>
/// Internal helpers for SQLCipher key derivation and integrity checks.
/// </summary>
internal static class SqlCipherCrypto
{
    /// <summary>
    /// Derives the AES and HMAC keys from the supplied salt and password.
    /// </summary>
    public static (byte[] Key, byte[] HmacKey) DeriveKeys(SqlCipherConfiguration config, byte[] salt, byte[] password)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, config.KeyIterations, HashAlgorithmName.SHA1);
        byte[] key = pbkdf2.GetBytes(config.KeySize);

        byte[] hmacSalt = new byte[salt.Length];
        for (int i = 0; i < salt.Length; i++)
            hmacSalt[i] = (byte)(salt[i] ^ config.SaltMask);

        using var pbkdf2Hmac = new Rfc2898DeriveBytes(key, hmacSalt, config.HmacKeyIterations, HashAlgorithmName.SHA1);
        byte[] hmacKey = pbkdf2Hmac.GetBytes(config.HmacKeySize);
        return (key, hmacKey);
    }

    /// <summary>
    /// Computes the SQLCipher-style HMAC for a page.
    /// </summary>
    public static byte[] ComputeHmac(byte[] hmacKey, byte[] encryptedContent, byte[] iv, int pageNumber)
    {
        using var hmacSha1 = new HMACSHA1(hmacKey);

        Span<byte> pageNumberBytes = stackalloc byte[sizeof(uint)];
        BitConverter.TryWriteBytes(pageNumberBytes, (uint)pageNumber);
        if (!BitConverter.IsLittleEndian)
            pageNumberBytes.Reverse();

        byte[] data = new byte[encryptedContent.Length + iv.Length + pageNumberBytes.Length];
        Buffer.BlockCopy(encryptedContent, 0, data, 0, encryptedContent.Length);
        Buffer.BlockCopy(iv, 0, data, encryptedContent.Length, iv.Length);
        pageNumberBytes.CopyTo(data.AsSpan(encryptedContent.Length + iv.Length));
        return hmacSha1.ComputeHash(data);
    }
}
