namespace SQLCipherSharp3;

/// <summary>
/// Exception thrown when HMAC validation fails due to an incorrect password or corrupted data.
/// </summary>
/// <param name="message">Details describing the failure.</param>
public class WrongPasswordException(string message) : Exception(message);
