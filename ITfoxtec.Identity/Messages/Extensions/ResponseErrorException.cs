using System;

namespace ITfoxtec.Identity.Messages
{
    [Serializable]
    public class ResponseErrorException : Exception
    {
        public string Error { get; }

        public ResponseErrorException() { }
        public ResponseErrorException(string error, string message) : this(error, message, null) { }
        public ResponseErrorException(string error, string message, Exception inner) : base($"Error: {error}. {message}", inner)
        {
            Error = error;
        }
        protected ResponseErrorException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
