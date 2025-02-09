#region

using System.Security.Cryptography;
using System.Text;

#endregion

namespace SQLCipherSharp3;

/// <summary>
/// Provides methods for encrypting plaintext SQLite databases into SQLCipher 3.x compatible files.
/// </summary>
public class SqlCipherEncryptor
{
    private readonly SqlCipherConfiguration _config;
    private readonly byte[] _sqliteHeader = "SQLite format 3\0"u8.ToArray();

    /// <summary>
    /// Creates a new SQLCipherEncryptor with the given configuration.
    /// If no configuration is provided, the default configuration is used.
    /// </summary>
    public SqlCipherEncryptor(SqlCipherConfiguration? config = null)
    {
        _config = config ?? new SqlCipherConfiguration();
    }

    /// <summary>
    /// Synchronously encrypts the given plaintext SQLite database into an SQLCipher 3.x file.
    /// </summary>
    private byte[] Encrypt(byte[] plaintext, byte[] password)
    {
        if (plaintext == null || plaintext.Length == 0)
            throw new ArgumentException("Plaintext data is empty.");

        //Determine the total number of pages (pad the final page if necessary)
        int totalPages = (plaintext.Length + _config.PageSize - 1) / _config.PageSize;

        //Split the plaintext into pages. Any incomplete page is zero‑padded.
        byte[][] plaintextPages = new byte[totalPages][];
        for (int i = 0; i < totalPages; i++)
        {
            plaintextPages[i] = new byte[_config.PageSize];
            int offset = i * _config.PageSize;
            int remaining = plaintext.Length - offset;
            int copyLength = remaining >= _config.PageSize ? _config.PageSize : remaining;
            Array.Copy(plaintext, offset, plaintextPages[i], 0, copyLength);
        }

        //Verify that page 1 starts with the standard SQLite header.
        if (!plaintextPages[0].Take(_sqliteHeader.Length).SequenceEqual(_sqliteHeader))
            throw new ArgumentException("Plaintext does not appear to be a valid SQLite database (header mismatch).");

        //Generate a random salt for page 1.
        byte[] salt = new byte[_config.SaltSize];
        RandomNumberGenerator.Fill(salt);

        //Derive AES and HMAC keys.
        (byte[] key, byte[] hmacKey) = DeriveKeys(salt, password);

        //Prepare array to hold the encrypted pages.
        byte[][] encryptedPages = new byte[totalPages][];

        //--- Process Page 1 ---
        //For page 1, only a part of the page (after the header) is encrypted.
        int effectiveLengthPage1 = _config.PageSize - _config.SaltSize - _config.ReserveSize;
        byte[] plaintextBlockPage1 = new byte[effectiveLengthPage1];
        Array.Copy(plaintextPages[0], _config.SaltSize, plaintextBlockPage1, 0, effectiveLengthPage1);

        //Generate a random IV.
        byte[] iv = new byte[_config.IvSize];
        RandomNumberGenerator.Fill(iv);

        //Encrypt the effective plaintext block.
        byte[] encryptedBlockPage1 = EncryptAes(plaintextBlockPage1, key, iv);

        //Compute HMAC for page 1.
        byte[] hmac = ComputeHmac(hmacKey, encryptedBlockPage1, iv, 1);

        //Build the reserve region: IV + HMAC + optional filler.
        byte[] reserve = new byte[_config.ReserveSize];
        Buffer.BlockCopy(iv, 0, reserve, 0, _config.IvSize);
        Buffer.BlockCopy(hmac, 0, reserve, _config.IvSize, _config.HmacSize);
        int reserveFillerLen = _config.ReserveSize - _config.IvSize - _config.HmacSize;
        if (reserveFillerLen > 0)
        {
            byte[] filler = new byte[reserveFillerLen];
            RandomNumberGenerator.Fill(filler);
            Buffer.BlockCopy(filler, 0, reserve, _config.IvSize + _config.HmacSize, reserveFillerLen);
        }

        //Assemble encrypted page 1: salt + encrypted block + reserve.
        encryptedPages[0] = new byte[_config.PageSize];
        Buffer.BlockCopy(salt, 0, encryptedPages[0], 0, _config.SaltSize);
        Buffer.BlockCopy(encryptedBlockPage1, 0, encryptedPages[0], _config.SaltSize, encryptedBlockPage1.Length);
        Buffer.BlockCopy(reserve, 0, encryptedPages[0], _config.SaltSize + encryptedBlockPage1.Length, reserve.Length);

        //--- Process Pages 2 to totalPages ---
        //For pages 2 and onward, the effective plaintext is the first (PageSize - ReserveSize) bytes.
        int effectiveLengthOther = _config.PageSize - _config.ReserveSize;
        for (int i = 2; i <= totalPages; i++)
        {
            byte[] plaintextBlock = new byte[effectiveLengthOther];
            Array.Copy(plaintextPages[i - 1], 0, plaintextBlock, 0, effectiveLengthOther);

            byte[] ivI = new byte[_config.IvSize];
            RandomNumberGenerator.Fill(ivI);
            byte[] encryptedBlock = EncryptAes(plaintextBlock, key, ivI);
            byte[] hmacI = ComputeHmac(hmacKey, encryptedBlock, ivI, i);

            byte[] reserveI = new byte[_config.ReserveSize];
            Buffer.BlockCopy(ivI, 0, reserveI, 0, _config.IvSize);
            Buffer.BlockCopy(hmacI, 0, reserveI, _config.IvSize, _config.HmacSize);
            int fillerLen = _config.ReserveSize - _config.IvSize - _config.HmacSize;
            if (fillerLen > 0)
            {
                byte[] filler = new byte[fillerLen];
                RandomNumberGenerator.Fill(filler);
                Buffer.BlockCopy(filler, 0, reserveI, _config.IvSize + _config.HmacSize, fillerLen);
            }

            encryptedPages[i - 1] = new byte[_config.PageSize];
            Buffer.BlockCopy(encryptedBlock, 0, encryptedPages[i - 1], 0, encryptedBlock.Length);
            Buffer.BlockCopy(reserveI, 0, encryptedPages[i - 1], encryptedBlock.Length, reserveI.Length);
        }

        //Concatenate all encrypted pages into one output.
        using MemoryStream ms = new MemoryStream();
        foreach (var page in encryptedPages)
            ms.Write(page, 0, page.Length);
        return ms.ToArray();
    }

    /// <summary>
    /// Asynchronously encrypts the given plaintext SQLite database into an SQLCipher 3.x file.
    /// </summary>
    public async Task<byte[]> EncryptAsync(byte[] plaintext, byte[] password) => await Task.Run(() => Encrypt(plaintext, password)).ConfigureAwait(false);

    #region Helper Methods for Encryptor

    private (byte[] key, byte[] hmacKey) DeriveKeys(byte[] salt, byte[] password)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _config.KeyIterations, HashAlgorithmName.SHA1);
        byte[] key = pbkdf2.GetBytes(_config.KeySize);

        //Create a modified salt for HMAC key derivation by XORing each byte with the salt mask.
        byte[] hmacSalt = new byte[salt.Length];
        for (int i = 0; i < salt.Length; i++)
            hmacSalt[i] = (byte)(salt[i] ^ _config.SaltMask);

        using var pbkdf2Hmac = new Rfc2898DeriveBytes(key, hmacSalt, _config.HmacKeyIterations, HashAlgorithmName.SHA1);
        byte[] hmacKey = pbkdf2Hmac.GetBytes(_config.HmacKeySize);
        return (key, hmacKey);
    }

    private byte[] ComputeHmac(byte[] hmacKey, byte[] encryptedContent, byte[] iv, int pageNumber)
    {
        using var hmacSha1 = new HMACSHA1(hmacKey);
        byte[] pageNumberBytes = BitConverter.GetBytes((uint)pageNumber);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(pageNumberBytes);

        byte[] data = new byte[encryptedContent.Length + iv.Length + pageNumberBytes.Length];
        Buffer.BlockCopy(encryptedContent, 0, data, 0, encryptedContent.Length);
        Buffer.BlockCopy(iv, 0, data, encryptedContent.Length, iv.Length);
        Buffer.BlockCopy(pageNumberBytes, 0, data, encryptedContent.Length + iv.Length, pageNumberBytes.Length);
        return hmacSha1.ComputeHash(data);
    }

    private byte[] EncryptAes(byte[] plainTextBlock, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.KeySize = 256;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plainTextBlock, 0, plainTextBlock.Length);
    }

    #endregion
}