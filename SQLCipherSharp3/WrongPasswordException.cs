namespace SQLCipherSharp3;

/// <summary>
/// Exception thrown when the provided password is incorrect.
/// </summary>
public class WrongPasswordException(string message) : Exception(message);