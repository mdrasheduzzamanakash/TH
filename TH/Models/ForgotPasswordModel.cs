using System.ComponentModel.DataAnnotations;

namespace TH.Models
{
    public class ForgotPasswordModel : BaseModel
    {
        [Required]
        public string Email { get; set; }
    }
}
