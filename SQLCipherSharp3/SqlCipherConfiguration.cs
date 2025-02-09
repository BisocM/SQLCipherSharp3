namespace SQLCipherSharp3;

public class SqlCipherConfiguration
{
    //File layout parameters
    public int SaltSize { get; set; } = 16;      //16-byte salt at start of page 1
    public int PageSize { get; set; } = 1024;      //Default SQLite page size
    public int ReserveSize { get; set; } = 48;     //Bytes reserved at end of each page for HMAC/IV

    //Cryptographic parameters
    public int KeySize { get; set; } = 32;           //256-bit AES key
    public int KeyIterations { get; set; } = 64000;  //Iterations for PBKDF2 (AES key)
    public int HmacKeySize { get; set; } = 32;       //HMAC key size in bytes
    public int HmacKeyIterations { get; set; } = 2;  //Iterations for PBKDF2 (HMAC key)
    public int IvSize { get; set; } = 16;            //AES block size (IV length)
    public int HmacSize { get; set; } = 20;          //SHA1 produces a 20-byte hash

    //Salt mask for HMAC key derivation (XOR each salt byte with this value)
    public byte SaltMask { get; set; } = 0x3a;
}