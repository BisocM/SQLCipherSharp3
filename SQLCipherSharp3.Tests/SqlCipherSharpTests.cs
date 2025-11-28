#region

using System.Reflection;
using System.Text;
using Xunit;
using Assert = Xunit.Assert;

#endregion

namespace SQLCipherSharp3.Tests
{
    public class SqlCipherSharpTests
    {
        //Assume sample files are in the same folder as the test assembly.
        private readonly string _testDirectory =
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
            ?? throw new InvalidOperationException("Unable to locate test directory.");
        private string SampleEncDatabasePath => Path.Combine(_testDirectory, "sample_enc.db");
        private string SampleDatabasePath => Path.Combine(_testDirectory, "sample.db");

        private const string SamplePassword = "SAMPLE_PWD";
        private readonly SqlCipherDecryptor _decryptor = new();
        private readonly SqlCipherEncryptor _encryptor = new();

        [Fact]
        public void Decrypt_Synchronous_ValidPassword_ReturnsExpectedDatabase()
        {
            //Arrange
            byte[] encryptedData = File.ReadAllBytes(SampleEncDatabasePath);
            byte[] expectedData = File.ReadAllBytes(SampleDatabasePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);

            //Act
            byte[] decryptedData = _decryptor.Decrypt(encryptedData, passwordBytes);

            //Assert
            AssertDecryptedDatabasesEqual(expectedData, decryptedData);
        }

        [Fact]
        public async Task Decrypt_Asynchronous_ValidPassword_ReturnsExpectedDatabase()
        {
            //Arrange
            byte[] encryptedData = await File.ReadAllBytesAsync(SampleEncDatabasePath);
            byte[] expectedData = await File.ReadAllBytesAsync(SampleDatabasePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);

            //Act
            byte[] decryptedData = await _decryptor.DecryptAsync(encryptedData, passwordBytes);

            //Assert
            AssertDecryptedDatabasesEqual(expectedData, decryptedData);
        }

        [Fact]
        public void Decrypt_Synchronous_InvalidPassword_ThrowsException()
        {
            //Arrange
            byte[] encryptedData = File.ReadAllBytes(SampleEncDatabasePath);
            byte[] wrongPasswordBytes = Encoding.UTF8.GetBytes("WRONG_PWD");

            //Act & Assert: expect a WrongPasswordException.
            var ex = Assert.Throws<WrongPasswordException>(() => _decryptor.Decrypt(encryptedData, wrongPasswordBytes));
            Assert.Contains("HMAC verification failed", ex.Message);
        }

        [Fact]
        public void Decrypt_Synchronous_EmptyPassword_ThrowsArgumentException()
        {
            byte[] encryptedData = File.ReadAllBytes(SampleEncDatabasePath);
            Assert.Throws<ArgumentException>(() => _decryptor.Decrypt(encryptedData, Array.Empty<byte>()));
        }

        [Fact]
        public void Encrypt_Synchronous_EmptyPassword_ThrowsArgumentException()
        {
            byte[] plaintext = File.ReadAllBytes(SampleDatabasePath);
            Assert.Throws<ArgumentException>(() => _encryptor.Encrypt(plaintext, Array.Empty<byte>()));
        }

        [Fact]
        public void Encrypt_Synchronous_NullPlaintext_ThrowsArgumentException()
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);
            Assert.Throws<ArgumentException>(() => _encryptor.Encrypt(null!, passwordBytes));
        }

        [Fact]
        public async Task Decrypt_Asynchronous_InvalidPassword_ThrowsException()
        {
            //Arrange
            byte[] encryptedData = File.ReadAllBytes(SampleEncDatabasePath);
            byte[] wrongPasswordBytes = Encoding.UTF8.GetBytes("WRONG_PWD");

            //Act & Assert: expect a WrongPasswordException.
            var ex = await Assert.ThrowsAsync<WrongPasswordException>(
                async () => await _decryptor.DecryptAsync(encryptedData, wrongPasswordBytes));
            Assert.Contains("HMAC verification failed", ex.Message);
        }

        [Fact]
        public void Decrypt_Synchronous_NullData_ThrowsArgumentException()
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);
            Assert.Throws<ArgumentException>(() => _decryptor.Decrypt(null!, passwordBytes));
        }

        [Fact]
        public async Task Decrypt_Asynchronous_NullData_ThrowsArgumentException()
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);
            await Assert.ThrowsAsync<ArgumentException>(async () => await _decryptor.DecryptAsync(null!, passwordBytes));
        }

        [Fact]
        public void Encrypt_Decrypt_RoundTrip_ReturnsOriginalDatabase()
        {
            byte[] plaintext = File.ReadAllBytes(SampleDatabasePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);

            byte[] encrypted = _encryptor.Encrypt(plaintext, passwordBytes);
            byte[] decrypted = _decryptor.Decrypt(encrypted, passwordBytes);

            AssertDecryptedDatabasesEqual(plaintext, decrypted);
        }

        [Fact]
        public async Task Encrypt_Decrypt_Asynchronous_RoundTrip_ReturnsOriginalDatabase()
        {
            byte[] plaintext = await File.ReadAllBytesAsync(SampleDatabasePath);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);

            byte[] encrypted = await _encryptor.EncryptAsync(plaintext, passwordBytes);
            byte[] decrypted = await _decryptor.DecryptAsync(encrypted, passwordBytes);

            AssertDecryptedDatabasesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Decrypt_Synchronous_TamperedSecondPage_ThrowsWrongPasswordException()
        {
            byte[] tampered = File.ReadAllBytes(SampleEncDatabasePath);
            var config = new SqlCipherConfiguration();
            int pageSize = config.PageSize;
            int reserveSize = config.ReserveSize;

            Assert.True(tampered.Length >= pageSize * 2, "Test database should be at least two pages.");

            int page2ReserveOffset = pageSize + (pageSize - reserveSize);
            tampered[page2ReserveOffset + config.IvSize] ^= 0xFF;

            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);
            var ex = Assert.Throws<WrongPasswordException>(() => _decryptor.Decrypt(tampered, passwordBytes));
            Assert.Contains("HMAC verification failed", ex.Message);
        }

        /// <summary>
        /// Compares two database files page by page, ignoring differences in the reserve region.
        /// Assumes a fixed page size and reserve size from the default configuration.
        /// </summary>
        private void AssertDecryptedDatabasesEqual(byte[] expected, byte[] actual)
        {
            //Create a default configuration instance to retrieve page size values.
            var defaultConfig = new SqlCipherConfiguration();
            int pageSize = defaultConfig.PageSize;
            int reserveSize = defaultConfig.ReserveSize;

            //Both files should have a whole number of pages.
            Assert.Equal(0, expected.Length % pageSize);
            Assert.Equal(0, actual.Length % pageSize);

            int totalPages = expected.Length / pageSize;
            Assert.Equal(totalPages, actual.Length / pageSize);

            for (int i = 0; i < totalPages; i++)
            {
                byte[] expectedPage = expected.Skip(i * pageSize).Take(pageSize).ToArray();
                byte[] actualPage = actual.Skip(i * pageSize).Take(pageSize).ToArray();

                if (i == 0)
                {
                    //For page 1, the first 16 bytes are the SQLite header.
                    Assert.True(expectedPage.Take(16).SequenceEqual(actualPage.Take(16)),
                        $"Header mismatch on page {i + 1}");

                    //Compare the remainder of the content up to the start of the reserve region.
                    int contentLength = pageSize - reserveSize;
                    Assert.True(expectedPage.Take(contentLength).SequenceEqual(actualPage.Take(contentLength)),
                        $"Page {i + 1} content (excluding reserve) differs.");
                }
                else
                {
                    //For pages 2+, compare the first (pageSize - reserveSize) bytes.
                    int contentLength = pageSize - reserveSize;
                    Assert.True(expectedPage.Take(contentLength).SequenceEqual(actualPage.Take(contentLength)),
                        $"Page {i + 1} content (excluding reserve) differs.");
                }
            }
        }
    }
}
