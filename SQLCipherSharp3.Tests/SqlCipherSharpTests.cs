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
        private readonly string _testDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        private string SampleEncDatabasePath => Path.Combine(_testDirectory, "sample_enc.db");
        private string SampleDatabasePath => Path.Combine(_testDirectory, "sample.db");

        private const string SamplePassword = "SAMPLE_PWD";
        private readonly SqlCipherDecryptor _decryptor = new(); //Uses the default configuration

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
            Assert.Throws<ArgumentException>(() => _decryptor.Decrypt(null, passwordBytes));
        }

        [Fact]
        public async Task Decrypt_Asynchronous_NullData_ThrowsArgumentException()
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(SamplePassword);
            await Assert.ThrowsAsync<ArgumentException>(async () => await _decryptor.DecryptAsync(null, passwordBytes));
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