using System.ComponentModel.DataAnnotations;

namespace TH.Models.Authentication.Register
{
    public class Register : BaseModel
    {
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
