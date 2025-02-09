#region

using System.Security.Cryptography;
using System.Text;

#endregion

namespace SQLCipherSharp3
{
    /// <summary>
    /// Provides methods for decrypting SQLCipher 3.x databases.
    /// </summary>
    public class SqlCipherDecryptor
    {
        private readonly SqlCipherConfiguration _config;
        private readonly byte[] _sqliteHeader = "SQLite format 3\0"u8.ToArray();

        /// <summary>
        /// Creates a new SQLCipherDecryptor with the given configuration.
        /// If no configuration is provided, the default configuration is used.
        /// </summary>
        public SqlCipherDecryptor(SqlCipherConfiguration? config = null)
        {
            _config = config ?? new SqlCipherConfiguration();
        }

        /// <summary>
        /// Synchronously decrypts the provided encrypted database using the given password.
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData, byte[] password)
        {
            if (encryptedData == null || encryptedData.Length < _config.SaltSize + _config.ReserveSize)
                throw new ArgumentException("Invalid encrypted data.");

            //Extract salt from page 1.
            byte[] salt = new byte[_config.SaltSize];
            Array.Copy(encryptedData, 0, salt, 0, _config.SaltSize);

            (byte[] key, byte[] hmacKey) = DeriveKeys(salt, password);

            int numPages = encryptedData.Length / _config.PageSize;
            if (encryptedData.Length % _config.PageSize != 0)
                numPages++;

            //Process Page 1.
            byte[] page1Raw = new byte[_config.PageSize];
            Array.Copy(encryptedData, 0, page1Raw, 0, _config.PageSize);
            if (_config.PageSize < _config.SaltSize)
                throw new Exception("Page 1 is too short.");

            byte[] page1Adjusted = new byte[_config.PageSize - _config.SaltSize];
            Array.Copy(page1Raw, _config.SaltSize, page1Adjusted, 0, _config.PageSize - _config.SaltSize);
            if (page1Adjusted.Length < _config.ReserveSize)
                throw new Exception("Page 1 is too short to contain a reserve region.");
            int encContentLen = page1Adjusted.Length - _config.ReserveSize;
            byte[] page1EncryptedContent = new byte[encContentLen];
            Array.Copy(page1Adjusted, 0, page1EncryptedContent, 0, encContentLen);
            byte[] page1Reserve = new byte[_config.ReserveSize];
            Array.Copy(page1Adjusted, encContentLen, page1Reserve, 0, _config.ReserveSize);
            if (page1Reserve.Length < _config.IvSize)
                throw new Exception("Page 1 reserve region too short for IV.");
            byte[] page1Iv = new byte[_config.IvSize];
            Array.Copy(page1Reserve, 0, page1Iv, 0, _config.IvSize);
            if (page1Reserve.Length < _config.IvSize + _config.HmacSize)
                throw new Exception("Page 1 reserve region too short for HMAC.");
            byte[] page1StoredHmac = new byte[_config.HmacSize];
            Array.Copy(page1Reserve, _config.IvSize, page1StoredHmac, 0, _config.HmacSize);

            byte[] page1ComputedHmac = ComputeHmac(hmacKey, page1EncryptedContent, page1Iv, 1);
            if (!page1StoredHmac.SequenceEqual(page1ComputedHmac))
                throw new WrongPasswordException("Wrong password (page 1 HMAC verification failed).");

            byte[] page1DecryptedContent = DecryptAes(page1EncryptedContent, key, page1Iv);
            if (page1DecryptedContent.Length != _config.PageSize - _config.SaltSize - _config.ReserveSize)
                throw new Exception("Unexpected decrypted content length for page 1.");

            //Assemble page 1: SQLite header + decrypted content + zero-filled reserve.
            byte[] filler = new byte[_config.ReserveSize]; //zeros by default
            byte[] page1Decrypted = new byte[_config.PageSize];
            Buffer.BlockCopy(_sqliteHeader, 0, page1Decrypted, 0, _sqliteHeader.Length);
            Buffer.BlockCopy(page1DecryptedContent, 0, page1Decrypted, _sqliteHeader.Length, page1DecryptedContent.Length);
            Buffer.BlockCopy(filler, 0, page1Decrypted, _sqliteHeader.Length + page1DecryptedContent.Length, filler.Length);

            //Process remaining pages synchronously.
            byte[][] decryptedPages = new byte[numPages][];
            decryptedPages[0] = page1Decrypted;
            for (int i = 1; i < numPages; i++)
            {
                int offset = i * _config.PageSize;
                int pageLength = Math.Min(_config.PageSize, encryptedData.Length - offset);
                byte[] page = new byte[pageLength];
                Array.Copy(encryptedData, offset, page, 0, pageLength);
                if (page.Length < _config.ReserveSize)
                    throw new Exception($"Page {i + 1} is too short to contain a reserve region.");
                int contentLen = page.Length - _config.ReserveSize;
                byte[] pageEncryptedContent = new byte[contentLen];
                Array.Copy(page, 0, pageEncryptedContent, 0, contentLen);
                byte[] pageReserve = new byte[_config.ReserveSize];
                Array.Copy(page, contentLen, pageReserve, 0, _config.ReserveSize);
                if (pageReserve.Length < _config.IvSize)
                    throw new Exception($"Page {i + 1} reserve region too short for IV.");
                byte[] pageIv = new byte[_config.IvSize];
                Array.Copy(pageReserve, 0, pageIv, 0, _config.IvSize);
                if (pageReserve.Length < _config.IvSize + _config.HmacSize)
                    throw new Exception($"Page {i + 1} reserve region too short for HMAC.");
                byte[] pageStoredHmac = new byte[_config.HmacSize];
                Array.Copy(pageReserve, _config.IvSize, pageStoredHmac, 0, _config.HmacSize);
                byte[] pageComputedHmac = ComputeHmac(hmacKey, pageEncryptedContent, pageIv, i + 1);
                if (!pageStoredHmac.SequenceEqual(pageComputedHmac))
                    throw new Exception($"HMAC verification failed for page {i + 1}.");
                byte[] pageDecryptedContent = DecryptAes(pageEncryptedContent, key, pageIv);
                byte[] pageFiller = new byte[_config.ReserveSize];
                byte[] fullPage = new byte[pageDecryptedContent.Length + pageFiller.Length];
                Buffer.BlockCopy(pageDecryptedContent, 0, fullPage, 0, pageDecryptedContent.Length);
                Buffer.BlockCopy(pageFiller, 0, fullPage, pageDecryptedContent.Length, pageFiller.Length);
                decryptedPages[i] = fullPage;
            }

            //Concatenate all decrypted pages.
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (var p in decryptedPages)
                    ms.Write(p, 0, p.Length);
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Asynchronously decrypts the provided encrypted database using the given password.
        /// </summary>
        public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] password)
        {
            if (encryptedData == null || encryptedData.Length < _config.SaltSize + _config.ReserveSize)
                throw new ArgumentException("Invalid encrypted data.");

            //Extract salt from page 1.
            byte[] salt = new byte[_config.SaltSize];
            Array.Copy(encryptedData, 0, salt, 0, _config.SaltSize);

            (byte[] key, byte[] hmacKey) = DeriveKeys(salt, password);

            int numPages = encryptedData.Length / _config.PageSize;
            if (encryptedData.Length % _config.PageSize != 0)
                numPages++;

            //Process page 1 synchronously.
            byte[] page1Raw = new byte[_config.PageSize];
            Array.Copy(encryptedData, 0, page1Raw, 0, _config.PageSize);
            if (_config.PageSize < _config.SaltSize)
                throw new Exception("Page 1 is too short.");

            byte[] page1Adjusted = new byte[_config.PageSize - _config.SaltSize];
            Array.Copy(page1Raw, _config.SaltSize, page1Adjusted, 0, _config.PageSize - _config.SaltSize);
            if (page1Adjusted.Length < _config.ReserveSize)
                throw new Exception("Page 1 is too short to contain a reserve region.");
            int encContentLen = page1Adjusted.Length - _config.ReserveSize;
            byte[] page1EncryptedContent = new byte[encContentLen];
            Array.Copy(page1Adjusted, 0, page1EncryptedContent, 0, encContentLen);
            byte[] page1Reserve = new byte[_config.ReserveSize];
            Array.Copy(page1Adjusted, encContentLen, page1Reserve, 0, _config.ReserveSize);
            if (page1Reserve.Length < _config.IvSize)
                throw new Exception("Page 1 reserve region too short for IV.");
            byte[] page1Iv = new byte[_config.IvSize];
            Array.Copy(page1Reserve, 0, page1Iv, 0, _config.IvSize);
            if (page1Reserve.Length < _config.IvSize + _config.HmacSize)
                throw new Exception("Page 1 reserve region too short for HMAC.");
            byte[] page1StoredHmac = new byte[_config.HmacSize];
            Array.Copy(page1Reserve, _config.IvSize, page1StoredHmac, 0, _config.HmacSize);
            byte[] page1ComputedHmac = ComputeHmac(hmacKey, page1EncryptedContent, page1Iv, 1);
            if (!page1StoredHmac.SequenceEqual(page1ComputedHmac))
                throw new WrongPasswordException("Wrong password (page 1 HMAC verification failed).");
            byte[] page1DecryptedContent = DecryptAes(page1EncryptedContent, key, page1Iv);
            if (page1DecryptedContent.Length != _config.PageSize - _config.SaltSize - _config.ReserveSize)
                throw new Exception("Unexpected decrypted content length for page 1.");
            byte[] filler = new byte[_config.ReserveSize];
            byte[] page1Decrypted = new byte[_config.PageSize];
            Buffer.BlockCopy(_sqliteHeader, 0, page1Decrypted, 0, _sqliteHeader.Length);
            Buffer.BlockCopy(page1DecryptedContent, 0, page1Decrypted, _sqliteHeader.Length, page1DecryptedContent.Length);
            Buffer.BlockCopy(filler, 0, page1Decrypted, _sqliteHeader.Length + page1DecryptedContent.Length, filler.Length);

            //Process remaining pages asynchronously.
            Task<byte[]>[] tasks = new Task<byte[]>[numPages - 1];
            for (int i = 1; i < numPages; i++)
            {
                int pageIndex = i;
                tasks[pageIndex - 1] = Task.Run(() =>
                {
                    int offset = pageIndex * _config.PageSize;
                    int pageLength = Math.Min(_config.PageSize, encryptedData.Length - offset);
                    byte[] page = new byte[pageLength];
                    Array.Copy(encryptedData, offset, page, 0, pageLength);
                    if (page.Length < _config.ReserveSize)
                        throw new Exception($"Page {pageIndex + 1} is too short to contain a reserve region.");
                    int contentLen = page.Length - _config.ReserveSize;
                    byte[] pageEncryptedContent = new byte[contentLen];
                    Array.Copy(page, 0, pageEncryptedContent, 0, contentLen);
                    byte[] pageReserve = new byte[_config.ReserveSize];
                    Array.Copy(page, contentLen, pageReserve, 0, _config.ReserveSize);
                    if (pageReserve.Length < _config.IvSize)
                        throw new Exception($"Page {pageIndex + 1} reserve region too short for IV.");
                    byte[] pageIv = new byte[_config.IvSize];
                    Array.Copy(pageReserve, 0, pageIv, 0, _config.IvSize);
                    if (pageReserve.Length < _config.IvSize + _config.HmacSize)
                        throw new Exception($"Page {pageIndex + 1} reserve region too short for HMAC.");
                    byte[] pageStoredHmac = new byte[_config.HmacSize];
                    Array.Copy(pageReserve, _config.IvSize, pageStoredHmac, 0, _config.HmacSize);
                    byte[] pageComputedHmac = ComputeHmac(hmacKey, pageEncryptedContent, pageIv, pageIndex + 1);
                    if (!pageStoredHmac.SequenceEqual(pageComputedHmac))
                        throw new Exception($"HMAC verification failed for page {pageIndex + 1}.");
                    byte[] pageDecryptedContent = DecryptAes(pageEncryptedContent, key, pageIv);
                    byte[] pageFiller = new byte[_config.ReserveSize];
                    byte[] fullPage = new byte[pageDecryptedContent.Length + pageFiller.Length];
                    Buffer.BlockCopy(pageDecryptedContent, 0, fullPage, 0, pageDecryptedContent.Length);
                    Buffer.BlockCopy(pageFiller, 0, fullPage, pageDecryptedContent.Length, pageFiller.Length);
                    return fullPage;
                });
            }
            byte[][] decryptedPages = new byte[numPages][];
            decryptedPages[0] = page1Decrypted;
            byte[][] remainingPages = await Task.WhenAll(tasks).ConfigureAwait(false);
            for (int i = 1; i < numPages; i++)
                decryptedPages[i] = remainingPages[i - 1];

            using MemoryStream ms = new MemoryStream();
            foreach (var p in decryptedPages)
                ms.Write(p, 0, p.Length);
            return ms.ToArray();
        }

        #region Helper Methods for Decryptor

        private (byte[] key, byte[] hmacKey) DeriveKeys(byte[] salt, byte[] password)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _config.KeyIterations, HashAlgorithmName.SHA1);
            byte[] key = pbkdf2.GetBytes(_config.KeySize);

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

        #endregion
    }
}