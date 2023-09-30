using Microsoft.IdentityModel.Tokens;

namespace TH
{
    public static class THDefaults
    {
        public const string AppName = "TH";
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
        public const string AspToken = "AspToken";
        public const string Refresh = "refresh";
        public const string OneTimeMessage = "OTM";
        public const string OTMActive = "OtmActive";

        // Data layer
        public const string CookieDatalayerUserRole = "role";

        // Redirection 
        public const string RedirectUrl = "RedirectUrl";
        public const string LoginUrl = "/Auth/Login";
        public const string LogoutUrl = "/Auth/Logout";
        public const string AccessDeniedUrl = "/Auth/AccessDenied";
        public const string TokenRefreshUrl = "/Auth/RefreshToken";

        // Cache types
        public const string CacheTypeUserClaims = "CacheTypeUserRoles";
        public const string CacheTypeEmailJustVerified = "CacheTypeEmailJustVerified";
        public const string CacheTypeCustomer = "CacheTypeCustomer";


    }
}
