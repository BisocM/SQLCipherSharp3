using System.Security.Cryptography;

namespace SQLCipherSharp3;

/// <summary>
/// Decrypts SQLCipher 3.x database files.
/// </summary>
public class SqlCipherDecryptor
{
    private readonly SqlCipherConfiguration _config;
    private readonly byte[] _sqliteHeader = "SQLite format 3\0"u8.ToArray();

    /// <summary>
    /// Initializes a new decryptor instance.
    /// </summary>
    /// <param name="config">Optional configuration to override defaults.</param>
    public SqlCipherDecryptor(SqlCipherConfiguration? config = null)
    {
        _config = config ?? new SqlCipherConfiguration();
        _config.Validate();
    }

    /// <summary>
    /// Decrypts the provided encrypted SQLCipher database using the supplied password.
    /// </summary>
    /// <param name="encryptedData">SQLCipher 3.x database bytes.</param>
    /// <param name="password">Password used for key derivation.</param>
    /// <returns>Plaintext SQLite database bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when inputs are invalid or empty.</exception>
    /// <exception cref="WrongPasswordException">Thrown when HMAC validation fails.</exception>
    public byte[] Decrypt(byte[] encryptedData, byte[] password)
    {
        if (encryptedData == null || encryptedData.Length < _config.SaltSize + _config.ReserveSize)
            throw new ArgumentException("Encrypted data is missing required headers.", nameof(encryptedData));
        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));

        _config.Validate();

        if (encryptedData.Length < _config.PageSize)
            throw new ArgumentException("Encrypted data does not contain a full first page.", nameof(encryptedData));

        int numPages = encryptedData.Length / _config.PageSize;
        if (encryptedData.Length % _config.PageSize != 0)
            numPages++;

        byte[] salt = new byte[_config.SaltSize];
        Array.Copy(encryptedData, 0, salt, 0, _config.SaltSize);

        (byte[] key, byte[] hmacKey) = SqlCipherCrypto.DeriveKeys(_config, salt, password);

        byte[] page1Raw = new byte[_config.PageSize];
        Array.Copy(encryptedData, 0, page1Raw, 0, _config.PageSize);

        byte[] page1Adjusted = new byte[_config.PageSize - _config.SaltSize];
        Array.Copy(page1Raw, _config.SaltSize, page1Adjusted, 0, _config.PageSize - _config.SaltSize);

        if (page1Adjusted.Length < _config.ReserveSize)
            throw new ArgumentException("Page 1 is too short to contain a reserve region.", nameof(encryptedData));

        int encContentLen = page1Adjusted.Length - _config.ReserveSize;
        byte[] page1EncryptedContent = new byte[encContentLen];
        Array.Copy(page1Adjusted, 0, page1EncryptedContent, 0, encContentLen);

        byte[] page1Reserve = new byte[_config.ReserveSize];
        Array.Copy(page1Adjusted, encContentLen, page1Reserve, 0, _config.ReserveSize);
        if (page1Reserve.Length < _config.IvSize + _config.HmacSize)
            throw new ArgumentException("Page 1 reserve region is incomplete.", nameof(encryptedData));

        byte[] page1Iv = new byte[_config.IvSize];
        Array.Copy(page1Reserve, 0, page1Iv, 0, _config.IvSize);
        byte[] page1StoredHmac = new byte[_config.HmacSize];
        Array.Copy(page1Reserve, _config.IvSize, page1StoredHmac, 0, _config.HmacSize);

        byte[] page1ComputedHmac = SqlCipherCrypto.ComputeHmac(hmacKey, page1EncryptedContent, page1Iv, 1);
        if (!CryptographicOperations.FixedTimeEquals(page1StoredHmac, page1ComputedHmac))
            throw new WrongPasswordException("Wrong password or data corrupted (HMAC verification failed).");

        byte[] page1DecryptedContent = DecryptAes(page1EncryptedContent, key, page1Iv);
        if (page1DecryptedContent.Length != _config.PageSize - _config.SaltSize - _config.ReserveSize)
            throw new InvalidDataException("Unexpected decrypted content length for page 1.");

        byte[] filler = new byte[_config.ReserveSize];
        byte[] page1Decrypted = new byte[_config.PageSize];
        Buffer.BlockCopy(_sqliteHeader, 0, page1Decrypted, 0, _sqliteHeader.Length);
        Buffer.BlockCopy(page1DecryptedContent, 0, page1Decrypted, _sqliteHeader.Length, page1DecryptedContent.Length);
        Buffer.BlockCopy(filler, 0, page1Decrypted, _sqliteHeader.Length + page1DecryptedContent.Length, filler.Length);

        byte[][] decryptedPages = new byte[numPages][];
        decryptedPages[0] = page1Decrypted;

        for (int i = 1; i < numPages; i++)
        {
            int offset = i * _config.PageSize;
            int pageLength = Math.Min(_config.PageSize, encryptedData.Length - offset);
            byte[] page = new byte[pageLength];
            Array.Copy(encryptedData, offset, page, 0, pageLength);

            if (page.Length < _config.ReserveSize)
                throw new ArgumentException($"Page {i + 1} is too short to contain a reserve region.", nameof(encryptedData));

            int contentLen = page.Length - _config.ReserveSize;
            if (contentLen <= 0 || contentLen % _config.IvSize != 0)
                throw new InvalidDataException($"Page {i + 1} content size is invalid.");

            byte[] pageEncryptedContent = new byte[contentLen];
            Array.Copy(page, 0, pageEncryptedContent, 0, contentLen);
            byte[] pageReserve = new byte[_config.ReserveSize];
            Array.Copy(page, contentLen, pageReserve, 0, _config.ReserveSize);

            if (pageReserve.Length < _config.IvSize + _config.HmacSize)
                throw new ArgumentException($"Page {i + 1} reserve region is incomplete.", nameof(encryptedData));

            byte[] pageIv = new byte[_config.IvSize];
            Array.Copy(pageReserve, 0, pageIv, 0, _config.IvSize);
            byte[] pageStoredHmac = new byte[_config.HmacSize];
            Array.Copy(pageReserve, _config.IvSize, pageStoredHmac, 0, _config.HmacSize);

            byte[] pageComputedHmac = SqlCipherCrypto.ComputeHmac(hmacKey, pageEncryptedContent, pageIv, i + 1);
            if (!CryptographicOperations.FixedTimeEquals(pageStoredHmac, pageComputedHmac))
                throw new WrongPasswordException("Wrong password or data corrupted (HMAC verification failed).");

            byte[] pageDecryptedContent = DecryptAes(pageEncryptedContent, key, pageIv);
            byte[] pageFiller = new byte[_config.ReserveSize];
            byte[] fullPage = new byte[_config.PageSize];
            Buffer.BlockCopy(pageDecryptedContent, 0, fullPage, 0, pageDecryptedContent.Length);
            Buffer.BlockCopy(pageFiller, 0, fullPage, pageDecryptedContent.Length, pageFiller.Length);
            decryptedPages[i] = fullPage;
        }

        using MemoryStream ms = new MemoryStream();
        foreach (var p in decryptedPages)
            ms.Write(p, 0, p.Length);
        return ms.ToArray();
    }

    /// <summary>
    /// Asynchronously decrypts the provided encrypted SQLCipher database.
    /// </summary>
    /// <param name="encryptedData">SQLCipher 3.x database bytes.</param>
    /// <param name="password">Password used for key derivation.</param>
    /// <returns>Plaintext SQLite database bytes.</returns>
    public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] password) =>
        await Task.Run(() => Decrypt(encryptedData, password)).ConfigureAwait(false);

    private byte[] DecryptAes(byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
    }
}
