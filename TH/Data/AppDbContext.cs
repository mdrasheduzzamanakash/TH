using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TH.Domains;

namespace TH.Data
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
        #region Application part 

        public virtual DbSet<Customer> Customers { get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
        public virtual DbSet<Log> Logs { get; set; }


        #endregion

        #region Identity part 
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRole(builder);
        }

        private static void SeedRole(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole() { Name = THDefaults.Admin, ConcurrencyStamp = "1", NormalizedName = "Admin"},
                    new IdentityRole() { Name = THDefaults.Doctor, ConcurrencyStamp = "2", NormalizedName = "Doctor" },
                    new IdentityRole() { Name = THDefaults.DoctorUnverified, ConcurrencyStamp = "3", NormalizedName = "DoctorUnvarified" },
                    new IdentityRole() { Name = THDefaults.Patient, ConcurrencyStamp = "4", NormalizedName = "Patient" },
                    new IdentityRole() { Name = THDefaults.PatientUnverified, ConcurrencyStamp = "5", NormalizedName = "PatientUnvarified" },
                    new IdentityRole() { Name = THDefaults.Guest, ConcurrencyStamp = "6", NormalizedName = "Guest" }
                );
            
        }
        #endregion
    }

}
