using Microsoft.IdentityModel.Tokens;

namespace TH
{
    public static class THDefaults
    {
        public const string Active = "true";
        public const string Deactive = "false";
        // Roles 
        public const string Admin = "Admin";
        public const string Doctor = "Doctor";
        public const string DoctorUnverified = "DoctorUnverified";
        public const string Patient = "Patient";
        public const string PatientUnverified = "PatientUnverified";
        public const string Guest = "Guest";

        // Log
        public const string Urgent = "Urgent";
        public const string Fluid = "Important";
        public const string Loose = "Loose";
        public const string Error = "Error";
        public const string Information = "Information";
        public const string Warning = "Warning";

        // Token 
        public const string jwtAlgo = SecurityAlgorithms.HmacSha256;
        public const string Jwt = "jwt";
        public const string Refresh = "refresh";
        public const string OneTimeMessage = "OTM";
        public const string OTMActive = "false";

        // Redirection 
        public const string RedirectUrl = "";
    }
}
