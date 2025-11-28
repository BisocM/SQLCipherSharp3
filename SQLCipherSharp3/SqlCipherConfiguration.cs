namespace SQLCipherSharp3;

/// <summary>
/// Encapsulates layout and cryptographic parameters for SQLCipher 3.x compatible files.
/// </summary>
public class SqlCipherConfiguration
{
    /// <summary>
    /// Size of the random salt that prefixes page 1.
    /// </summary>
    public int SaltSize { get; set; } = 16;

    /// <summary>
    /// SQLite page size used for both plaintext and encrypted databases.
    /// </summary>
    public int PageSize { get; set; } = 1024;

    /// <summary>
    /// Bytes reserved at the end of each page for IV, HMAC, and filler.
    /// </summary>
    public int ReserveSize { get; set; } = 48;

    /// <summary>
    /// AES key size in bytes (SQLCipher 3.x uses 256-bit keys).
    /// </summary>
    public int KeySize { get; set; } = 32;

    /// <summary>
    /// PBKDF2 iteration count for deriving the AES key.
    /// </summary>
    public int KeyIterations { get; set; } = 64000;

    /// <summary>
    /// HMAC key size in bytes.
    /// </summary>
    public int HmacKeySize { get; set; } = 32;

    /// <summary>
    /// PBKDF2 iteration count for deriving the HMAC key.
    /// </summary>
    public int HmacKeyIterations { get; set; } = 2;

    /// <summary>
    /// AES block size (IV length) in bytes.
    /// </summary>
    public int IvSize { get; set; } = 16;

    /// <summary>
    /// HMAC output size in bytes (SHA1 -> 20 bytes).
    /// </summary>
    public int HmacSize { get; set; } = 20;

    /// <summary>
    /// Salt mask applied when deriving the HMAC key.
    /// </summary>
    public byte SaltMask { get; set; } = 0x3a;

    /// <summary>
    /// Validates the configuration and throws <see cref="ArgumentOutOfRangeException"/> on invalid values.
    /// </summary>
    public void Validate()
    {
        if (SaltSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(SaltSize), "Salt size must be greater than zero.");
        if (SaltSize != 16)
            throw new ArgumentOutOfRangeException(nameof(SaltSize), "SQLCipher 3.x requires a 16-byte salt.");
        if (PageSize <= SaltSize + ReserveSize)
            throw new ArgumentOutOfRangeException(nameof(PageSize), "Page size must exceed the salt plus reserve sizes.");
        if (ReserveSize < IvSize + HmacSize)
            throw new ArgumentOutOfRangeException(nameof(ReserveSize), "Reserve size must be large enough to hold IV and HMAC.");
        if (KeySize <= 0)
            throw new ArgumentOutOfRangeException(nameof(KeySize), "Key size must be greater than zero.");
        if (HmacKeySize <= 0)
            throw new ArgumentOutOfRangeException(nameof(HmacKeySize), "HMAC key size must be greater than zero.");
        if (IvSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(IvSize), "IV size must be greater than zero.");
        if (HmacSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(HmacSize), "HMAC size must be greater than zero.");
        if (KeyIterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(KeyIterations), "Key iteration count must be greater than zero.");
        if (HmacKeyIterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(HmacKeyIterations), "HMAC key iteration count must be greater than zero.");

        int firstPagePayload = PageSize - SaltSize - ReserveSize;
        int otherPagePayload = PageSize - ReserveSize;
        if (firstPagePayload <= 0 || otherPagePayload <= 0)
            throw new ArgumentOutOfRangeException(nameof(PageSize), "Page size must exceed salt and reserve sizes.");

        if (firstPagePayload % IvSize != 0 || otherPagePayload % IvSize != 0)
            throw new ArgumentOutOfRangeException(nameof(PageSize), "Page payload must be aligned to the AES block size.");
    }
}
