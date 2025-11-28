using System.Security.Cryptography;

namespace SQLCipherSharp3;

/// <summary>
/// Encrypts plaintext SQLite databases into SQLCipher 3.x compatible files.
/// </summary>
public class SqlCipherEncryptor
{
    private readonly SqlCipherConfiguration _config;
    private readonly byte[] _sqliteHeader = "SQLite format 3\0"u8.ToArray();

    /// <summary>
    /// Initializes a new encryptor instance.
    /// </summary>
    /// <param name="config">Optional configuration to override defaults.</param>
    public SqlCipherEncryptor(SqlCipherConfiguration? config = null)
    {
        _config = config ?? new SqlCipherConfiguration();
        _config.Validate();
    }

    /// <summary>
    /// Encrypts a plaintext SQLite database into an SQLCipher 3.x compatible file.
    /// </summary>
    /// <param name="plaintext">Raw bytes of the plaintext SQLite database.</param>
    /// <param name="password">Password used for key derivation.</param>
    /// <returns>Encrypted SQLCipher database bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when inputs are null, empty, or the plaintext header is invalid.</exception>
    public byte[] Encrypt(byte[] plaintext, byte[] password)
    {
        if (plaintext == null || plaintext.Length == 0)
            throw new ArgumentException("Plaintext data is empty.", nameof(plaintext));
        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));

        _config.Validate();

        int totalPages = (plaintext.Length + _config.PageSize - 1) / _config.PageSize;

        byte[][] plaintextPages = new byte[totalPages][];
        for (int i = 0; i < totalPages; i++)
        {
            plaintextPages[i] = new byte[_config.PageSize];
            int offset = i * _config.PageSize;
            int remaining = plaintext.Length - offset;
            int copyLength = remaining >= _config.PageSize ? _config.PageSize : remaining;
            Array.Copy(plaintext, offset, plaintextPages[i], 0, copyLength);
        }

        if (!plaintextPages[0].Take(_sqliteHeader.Length).SequenceEqual(_sqliteHeader))
            throw new ArgumentException("Plaintext does not appear to be a valid SQLite database (header mismatch).", nameof(plaintext));

        byte[] salt = new byte[_config.SaltSize];
        RandomNumberGenerator.Fill(salt);

        (byte[] key, byte[] hmacKey) = SqlCipherCrypto.DeriveKeys(_config, salt, password);

        byte[][] encryptedPages = new byte[totalPages][];

        int effectiveLengthPage1 = _config.PageSize - _config.SaltSize - _config.ReserveSize;
        byte[] plaintextBlockPage1 = new byte[effectiveLengthPage1];
        Array.Copy(plaintextPages[0], _config.SaltSize, plaintextBlockPage1, 0, effectiveLengthPage1);

        byte[] iv = new byte[_config.IvSize];
        RandomNumberGenerator.Fill(iv);
        byte[] encryptedBlockPage1 = EncryptAes(plaintextBlockPage1, key, iv);

        byte[] hmac = SqlCipherCrypto.ComputeHmac(hmacKey, encryptedBlockPage1, iv, 1);

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

        encryptedPages[0] = new byte[_config.PageSize];
        Buffer.BlockCopy(salt, 0, encryptedPages[0], 0, _config.SaltSize);
        Buffer.BlockCopy(encryptedBlockPage1, 0, encryptedPages[0], _config.SaltSize, encryptedBlockPage1.Length);
        Buffer.BlockCopy(reserve, 0, encryptedPages[0], _config.SaltSize + encryptedBlockPage1.Length, reserve.Length);

        int effectiveLengthOther = _config.PageSize - _config.ReserveSize;
        for (int i = 2; i <= totalPages; i++)
        {
            byte[] plaintextBlock = new byte[effectiveLengthOther];
            Array.Copy(plaintextPages[i - 1], 0, plaintextBlock, 0, effectiveLengthOther);

            byte[] ivI = new byte[_config.IvSize];
            RandomNumberGenerator.Fill(ivI);
            byte[] encryptedBlock = EncryptAes(plaintextBlock, key, ivI);
            byte[] hmacI = SqlCipherCrypto.ComputeHmac(hmacKey, encryptedBlock, ivI, i);

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

        using MemoryStream ms = new MemoryStream();
        foreach (var page in encryptedPages)
            ms.Write(page, 0, page.Length);
        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts a plaintext SQLite database asynchronously.
    /// </summary>
    /// <param name="plaintext">Raw bytes of the plaintext SQLite database.</param>
    /// <param name="password">Password used for key derivation.</param>
    /// <returns>Encrypted SQLCipher database bytes.</returns>
    public async Task<byte[]> EncryptAsync(byte[] plaintext, byte[] password) =>
        await Task.Run(() => Encrypt(plaintext, password)).ConfigureAwait(false);

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
}
