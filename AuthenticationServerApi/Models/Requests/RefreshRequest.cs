using System.ComponentModel.DataAnnotations;

namespace AuthenticationServerApi.Models.Requests
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
