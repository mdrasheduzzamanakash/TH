using System.ComponentModel.DataAnnotations;

namespace TH.Models
{
    public class ResetPasswordModel : BaseModel
    {
        [Required(ErrorMessage = "You must provide a password")]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "The password and the confirm password do not match")]
        public string ConfirmPassword { get; set; }

        public string Email { get; set; }
        public string Token { get; set; }

    }
}
