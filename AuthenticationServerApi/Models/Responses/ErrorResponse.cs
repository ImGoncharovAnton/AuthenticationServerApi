namespace AuthenticationServerApi.Models.Responses
{
    public class ErrorResponse
    {
        public IEnumerable<string> ErrorMessages { get;  }

        public ErrorResponse(string errorMessage) : this(new List<string>() { errorMessage })
        {}

        public ErrorResponse(IEnumerable<string> errorMessages)
        {
            ErrorMessages = errorMessages;
        }
    }
}
