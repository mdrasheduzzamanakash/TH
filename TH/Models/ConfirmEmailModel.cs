﻿namespace TH.Models
{
    public class ConfirmEmailModel : BaseModel
    {
        public string Message { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }
}
