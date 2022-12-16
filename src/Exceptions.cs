using System;

namespace U2fWin10
{
    public class ErrorException : Exception
    {
        public ErrorException(string message, Exception innerException = null) : base(message, innerException)
        {
        }
    }

    public class CanceledException : ErrorException
    {
        public CanceledException(Exception innerException = null) : base("The operation is canceled by the user",
                                                                         innerException)
        {
        }
    }
}
